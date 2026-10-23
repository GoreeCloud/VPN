package instance

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sync"

	"github.com/dexidp/dex/storage"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/version"
)

// VersionInfo preserves the management API shape while remote release discovery is disabled
type VersionInfo struct {
	// CurrentVersion is the running management server version
	CurrentVersion string
	// DashboardVersion is empty until a trusted GoreeCloud release feed is qualified
	DashboardVersion string
	// ManagementVersion is empty until a trusted GoreeCloud release feed is qualified
	ManagementVersion string
	// ManagementUpdateAvailable stays false without independently verified release metadata
	ManagementUpdateAvailable bool
}

// Manager handles instance-level operations like initial setup.
type Manager interface {
	// IsSetupRequired checks if instance setup is required.
	// Returns true if embedded IDP is enabled and no accounts exist.
	IsSetupRequired(ctx context.Context) (bool, error)

	// CreateOwnerUser creates the initial owner user in the embedded IDP.
	// This should only be called when IsSetupRequired returns true.
	CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error)

	// RollbackSetup reverses a successful CreateOwnerUser by deleting the user
	// from the embedded IDP and reloading setupRequired from persistent state, so
	// /api/setup can be retried only when no accounts or local users remain. Used
	// when post-user steps (account or PAT creation) fail and the caller wants a
	// clean slate.
	RollbackSetup(ctx context.Context, userID string) error

	// GetVersionInfo returns version information for NetBird components.
	GetVersionInfo(ctx context.Context) (*VersionInfo, error)
}

type instanceStore interface {
	GetAccountsCounter(ctx context.Context) (int64, error)
}

type embeddedIdP interface {
	CreateUserWithPassword(ctx context.Context, email, password, name string) (*idp.UserData, error)
	DeleteUser(ctx context.Context, userID string) error
	GetAllAccounts(ctx context.Context) (map[string][]*idp.UserData, error)
}

// DefaultManager is the default implementation of Manager.
type DefaultManager struct {
	store              instanceStore
	embeddedIdpManager embeddedIdP

	setupRequired bool
	setupMu       sync.RWMutex
}

// NewManager creates a new instance manager.
// If idpManager is not an EmbeddedIdPManager, setup-related operations will return appropriate defaults.
func NewManager(ctx context.Context, store store.Store, idpManager idp.Manager) (Manager, error) {
	embeddedIdp, ok := idpManager.(*idp.EmbeddedIdPManager)

	m := &DefaultManager{
		store:         store,
		setupRequired: false,
	}

	if ok && embeddedIdp != nil {
		m.embeddedIdpManager = embeddedIdp
		err := m.loadSetupRequired(ctx)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *DefaultManager) loadSetupRequired(ctx context.Context) error {
	// Check if there are any accounts in the NetBird store
	numAccounts, err := m.store.GetAccountsCounter(ctx)
	if err != nil {
		return err
	}
	hasAccounts := numAccounts > 0

	// Check if there are any users in the embedded IdP (Dex)
	users, err := m.embeddedIdpManager.GetAllAccounts(ctx)
	if err != nil {
		return err
	}
	hasLocalUsers := len(users) > 0

	m.setupMu.Lock()
	m.setupRequired = !(hasAccounts || hasLocalUsers)
	m.setupMu.Unlock()

	return nil
}

// IsSetupRequired checks if instance setup is required.
// Setup is required when:
// 1. Embedded IDP is enabled
// 2. No accounts exist in the store
func (m *DefaultManager) IsSetupRequired(_ context.Context) (bool, error) {
	if m.embeddedIdpManager == nil {
		return false, nil
	}

	m.setupMu.RLock()
	defer m.setupMu.RUnlock()

	return m.setupRequired, nil
}

// CreateOwnerUser creates the initial owner user in the embedded IDP.
func (m *DefaultManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {

	if m.embeddedIdpManager == nil {
		return nil, errors.New("embedded IDP is not enabled")
	}

	if err := m.validateSetupInfo(email, password, name); err != nil {
		return nil, err
	}

	m.setupMu.Lock()
	defer m.setupMu.Unlock()

	if !m.setupRequired {
		return nil, status.Errorf(status.PreconditionFailed, "setup already completed")
	}

	if err := m.checkSetupRequiredFromDB(ctx); err != nil {
		var sErr *status.Error
		if errors.As(err, &sErr) && sErr.Type() == status.PreconditionFailed {
			m.setupRequired = false
		}
		return nil, err
	}

	userData, err := m.embeddedIdpManager.CreateUserWithPassword(ctx, email, password, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	m.setupRequired = false

	log.WithContext(ctx).Infof("created owner user %s in embedded IdP", email)

	return userData, nil
}

// RollbackSetup undoes a successful CreateOwnerUser: deletes the user from the
// embedded IDP and reloads setupRequired from persistent state.
func (m *DefaultManager) RollbackSetup(ctx context.Context, userID string) error {
	if m.embeddedIdpManager == nil {
		return errors.New("embedded IDP is not enabled")
	}

	var deleteErr error
	if err := m.embeddedIdpManager.DeleteUser(ctx, userID); err != nil {
		if isNotFoundError(err) {
			log.WithContext(ctx).Debugf("setup rollback user %s already deleted", userID)
		} else {
			deleteErr = fmt.Errorf("failed to delete user from embedded IdP: %w", err)
		}
	}

	if err := m.loadSetupRequired(ctx); err != nil {
		reloadErr := fmt.Errorf("failed to reload setup state after rollback: %w", err)
		if deleteErr != nil {
			return errors.Join(deleteErr, reloadErr)
		}
		return reloadErr
	}

	if deleteErr != nil {
		return deleteErr
	}

	log.WithContext(ctx).Infof("rolled back setup for user %s", userID)
	return nil
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, storage.ErrNotFound) {
		return true
	}
	if s, ok := status.FromError(err); ok {
		return s.Type() == status.NotFound
	}
	return false
}

func (m *DefaultManager) checkSetupRequiredFromDB(ctx context.Context) error {
	numAccounts, err := m.store.GetAccountsCounter(ctx)
	if err != nil {
		return fmt.Errorf("failed to check accounts: %w", err)
	}
	if numAccounts > 0 {
		return status.Errorf(status.PreconditionFailed, "setup already completed")
	}

	users, err := m.embeddedIdpManager.GetAllAccounts(ctx)
	if err != nil {
		return fmt.Errorf("failed to check IdP users: %w", err)
	}
	if len(users) > 0 {
		return status.Errorf(status.PreconditionFailed, "setup already completed")
	}

	return nil
}

func (m *DefaultManager) validateSetupInfo(email, password, name string) error {
	if email == "" {
		return status.Errorf(status.InvalidArgument, "email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid email format")
	}
	if name == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if password == "" {
		return status.Errorf(status.InvalidArgument, "password is required")
	}
	if len(password) < 8 {
		return status.Errorf(status.InvalidArgument, "password must be at least 8 characters")
	}
	if len(password) > 72 {
		return status.Errorf(status.InvalidArgument, "password must be at most 72 characters")
	}
	return nil
}

// GetVersionInfo returns the local management version without outbound discovery.
// The inherited NetBird release endpoints are not trusted GoreeCloud update
// channels. Until GoreeCloud qualifies signed release metadata, remote version
// fields remain empty and no update is advertised.
func (m *DefaultManager) GetVersionInfo(_ context.Context) (*VersionInfo, error) {
	return &VersionInfo{CurrentVersion: version.NetbirdVersion()}, nil
}
