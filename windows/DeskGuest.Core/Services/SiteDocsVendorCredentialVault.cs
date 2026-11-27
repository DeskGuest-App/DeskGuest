using DeskGuest.Shared.SiteDocs;
using DeskGuest.Shared.VendorAccess;

namespace DeskGuest.Core.Services;

// =====================================================================
// BD-SHARED-PLAT-3/F3 — SiteDocsVendorCredentialVault: the ONE
// production IVendorCredentialVault, backed by the FEATURES §8 site
// credential vault (SiteDocumentationService).
//
// Before this adapter, the only IVendorCredentialVault implementation
// was InMemoryVendorCredentialVault (dev/test): no persistence, no
// RBAC, no re-auth, no chained audit — and no adapter connected the
// vendor-pass injection path to the site vault whose "cred-" ids the
// pass references name. Resolving through this adapter runs the site
// vault's own injection discipline
// (SiteDocumentationService.ResolveCredentialForInjection):
//   * the credential's binding is verified (substituted material
//     resolves to nothing);
//   * a chained-audit `site_credential_injected` entry is appended
//     BEFORE the value leaves the vault;
//   * a DELETED site credential resolves to nothing, so deleting or
//     rotating a site credential takes effect on every pass that
//     references it (rotation changes the value the next injection
//     presents; deletion refuses it).
// Store() refuses: site credentials are created and rotated through
// the site vault's own human, re-authenticated paths — the vendor
// injection path never writes credential material.
// =====================================================================

/// <summary>Production vendor credential vault over the site
/// documentation vault. See the file header for the discipline.</summary>
public sealed class SiteDocsVendorCredentialVault : IVendorCredentialVault
{
    private readonly SiteDocumentationService _siteDocs;

    public SiteDocsVendorCredentialVault(SiteDocumentationService siteDocs) =>
        _siteDocs = siteDocs ?? throw new ArgumentNullException(nameof(siteDocs));

    public VaultCredentialHandle? ResolveForInjection(string credentialRef) =>
        _siteDocs.ResolveCredentialForInjection(credentialRef);

    public bool Contains(string credentialRef) =>
        _siteDocs.CredentialExistsForInjection(credentialRef);

    public void Store(string credentialRef, string credentialValue) =>
        throw new InvalidOperationException(
            "the site vault is the credential store of record: credentials are created through " +
            "SiteDocumentationService's human, re-authenticated paths — the vendor injection path never writes credential material");

    public bool Remove(string credentialRef) =>
        throw new InvalidOperationException(
            "the site vault is the credential store of record: credentials are deleted through " +
            "SiteDocumentationService's admin path — the vendor injection path never removes credential material");
}
