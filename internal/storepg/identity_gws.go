package storepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/gws"
	"defendsec/internal/gws/google"
)

// Google Workspace settings (migration 031). Runs and findings use the shared
// identity tables of migration 028 with provider "google".

// GWSSettings is the instance's one Google Workspace domain and how it is judged.
type GWSSettings struct {
	// Configured is true once an administrator to act as is set.
	Configured bool   `json:"configured"`
	AdminEmail string `json:"adminEmail"`
	// GmailScope is "readonly" (gmail.readonly) or "settings.basic"
	// (gmail.settings.basic): which Gmail scope the operator delegated.
	GmailScope     string     `json:"gmailScope"`
	SuperAdminMax  int        `json:"superAdminMax"`
	TrustedDomains []string   `json:"trustedDomains"`
	FinanceTerms   []string   `json:"financeTerms"`
	UpdatedBy      string     `json:"updatedBy,omitempty"`
	UpdatedAt      *time.Time `json:"updatedAt,omitempty"`
}

// The Gmail scope choices of GWSSettings.GmailScope.
const (
	GWSScopeReadonly      = "readonly"
	GWSScopeSettingsBasic = "settings.basic"
)

// GmailScopeURL is the OAuth scope the setting stands for.
func (g GWSSettings) GmailScopeURL() string {
	if g.GmailScope == GWSScopeSettingsBasic {
		return google.ScopeGmailSettingsBasic
	}
	return google.ScopeGmailReadonly
}

// DefaultGWSSettings are the settings of an instance that never saved any.
func DefaultGWSSettings() GWSSettings {
	return GWSSettings{GmailScope: GWSScopeReadonly, SuperAdminMax: gws.DefaultSuperAdminMax, TrustedDomains: []string{}, FinanceTerms: []string{}}
}

// GetGWSSettings returns the saved settings, or the defaults with Configured=false.
func (s *Store) GetGWSSettings(ctx context.Context) (GWSSettings, error) {
	out := DefaultGWSSettings()
	var at time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT admin_email, gmail_scope, super_admin_max, trusted_domains, finance_terms, updated_by, updated_at
		FROM gws_settings WHERE id = 1`).
		Scan(&out.AdminEmail, &out.GmailScope, &out.SuperAdminMax, &out.TrustedDomains, &out.FinanceTerms, &out.UpdatedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if out.TrustedDomains == nil {
		out.TrustedDomains = []string{}
	}
	if out.FinanceTerms == nil {
		out.FinanceTerms = []string{}
	}
	out.Configured = out.AdminEmail != ""
	out.UpdatedAt = &at
	return out, nil
}

// Normalize validates and cleans the settings in place.
func (g *GWSSettings) Normalize() error {
	g.AdminEmail = strings.ToLower(strings.TrimSpace(g.AdminEmail))
	if g.AdminEmail != "" && !google.ValidEmail(g.AdminEmail) {
		return fmt.Errorf("%w: the administrator must be the email address of a user of the domain", ErrBadIdentitySettings)
	}
	if g.GmailScope == "" {
		g.GmailScope = GWSScopeReadonly
	}
	if g.GmailScope != GWSScopeReadonly && g.GmailScope != GWSScopeSettingsBasic {
		return fmt.Errorf("%w: the Gmail scope must be %q or %q", ErrBadIdentitySettings, GWSScopeReadonly, GWSScopeSettingsBasic)
	}
	if g.SuperAdminMax < 1 || g.SuperAdminMax > 50 {
		return fmt.Errorf("%w: the super administrator limit must be between 1 and 50", ErrBadIdentitySettings)
	}
	var err error
	if g.TrustedDomains, err = cleanList(g.TrustedDomains, "trusted domain", 50, validDomain); err != nil {
		return err
	}
	if g.FinanceTerms, err = cleanList(g.FinanceTerms, "finance term", 50, func(s string) bool { return len(s) >= 3 && len(s) <= 40 }); err != nil {
		return err
	}
	return nil
}

// SetGWSSettings saves the settings and chains the change in the audit log in the
// same transaction.
func (s *Store) SetGWSSettings(ctx context.Context, actor string, in GWSSettings) error {
	if err := in.Normalize(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO gws_settings (id, admin_email, gmail_scope, super_admin_max, trusted_domains, finance_terms, updated_by, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (id) DO UPDATE SET admin_email = EXCLUDED.admin_email, gmail_scope = EXCLUDED.gmail_scope,
			super_admin_max = EXCLUDED.super_admin_max, trusted_domains = EXCLUDED.trusted_domains,
			finance_terms = EXCLUDED.finance_terms, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		in.AdminEmail, in.GmailScope, in.SuperAdminMax, in.TrustedDomains, in.FinanceTerms, actor); err != nil {
		return err
	}
	if err := auditInTx(ctx, tx, actor, "identity_settings_changed", "", map[string]any{
		"provider": gws.Provider, "adminEmail": in.AdminEmail, "gmailScope": in.GmailScope,
		"superAdminMax": in.SuperAdminMax, "trustedDomains": in.TrustedDomains, "financeTerms": in.FinanceTerms,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
