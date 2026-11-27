using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Provisioning;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-29 — OS imaging / provisioning + profile migration.
// Image definitions (versioned, hash-pinned, composed from RMM-16
// packages / RMM-07 policy / RMM-20 runbooks), provisioning runs as
// RMM-15 journal jobs under an RMM-03 signed authorization, profile
// migration as its OWN content type (never an RMM-16 package), and
// single-use bare-metal provisioning tokens. Executors are fakes;
// NOTHING here images a real machine.
public class Rmm29Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string User1 = "user-1";
    private const string User2 = "user-2";

    public static string H(string seed) => ProvisioningHashing.Sha256Hex(seed);

    public static OsImageDefinition Image(string id = "gold", string version = "1.0.0",
        string? driverSeed = "drivers-v1") => new(
            id, version, $"Gold {version}", true,
            "share://images/gold.wim", H("base-image-bytes"),
            "share://drivers/pack1", H(driverSeed ?? "drivers-v1"),
            new[] { "widget@2.0.0" }, new[] { "pol-base" }, "rb-post-provision", null);

    public static ProfileCaptureManifest Manifest(string device = Dev, string user = User1) => new(
        device, user, new[]
        {
            new ProfileManifestEntry("Documents/report.txt", ProfileCategories.Documents),
            new ProfileManifestEntry("Settings/app.ini", ProfileCategories.Settings),
        });

    public static FakeProfileCaptureSource FullSource() => new FakeProfileCaptureSource()
        .Add("Documents/report.txt", "quarterly numbers")
        .Add("Settings/app.ini", "theme=dark");

    // ---- runner-level rig ----------------------------------------------

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public DevOnlyPassThroughProtector Protector = new();
        public DeviceIdentity Customer;
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public ImageRepository Images = new();
        public ProfileMigrationEngine Profiles;
        public FakeProfileCaptureSource Capture = FullSource();
        public FakeImagingExecutor Imaging = new();
        public FakeEnrollmentSink Enrollment = new();
        public ProvisioningTokenService Tokens = new();
        public HashSet<string> Accepted = new(StringComparer.OrdinalIgnoreCase) { Dev };
        public Dictionary<string, CrossUserRestoreDecision> Decisions = new(StringComparer.Ordinal);
        public Func<string, string, OsImageDefinition?> LookupOverride;
        // D38 fix lane: the rig's devices live in scope "co-1"
        // (matching the Scope const) and hold no profiles unless a
        // test says otherwise.
        public Func<string, string?> ScopeOverride;
        public HashSet<string> DevicesWithProfiles = new(StringComparer.OrdinalIgnoreCase);
        public ProvisioningRunner Runner;

        public Rig()
        {
            Customer = new DeviceIdentity(Protector);
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Profiles = new ProfileMigrationEngine(Protector);
            Runner = new ProvisioningRunner(Gate, Audit, Profiles, Capture, Imaging, Enrollment, Tokens,
                (id, v) => LookupOverride is not null ? LookupOverride(id, v) : Images.Get(id, v),
                Images.IsRevoked, d => Accepted.Contains(d),
                id => Decisions.TryGetValue(id ?? "", out var dec) ? dec : null,
                d => ScopeOverride is not null ? ScopeOverride(d) : Scope,
                d => DevicesWithProfiles.Contains(d));
        }

        public SignedCommandEnvelope EnvelopeFor(ProvisioningRunRequest req) => Signer.Sign(
            SignedCommandClasses.Provisioning,
            Encoding.UTF8.GetBytes(ProvisioningBinding.Payload(req.RunId, req.Image, req.DeviceId,
                req.CaptureManifest is null ? null : ProvisioningBinding.CaptureManifestHash(req.CaptureManifest),
                req.Mode, req.TargetUserId, req.CrossUserDecision?.Id)),
            Now, TimeSpan.FromMinutes(30));

        public ProvisioningRunResult Run(ProvisioningRunRequest req, bool policy = true) =>
            Runner.Run(req, EnvelopeFor(req), new JobJournal(), () => policy, Now);

        public static ProvisioningRunRequest ReimageReq(string runId = "run-1", OsImageDefinition image = null,
            string device = Dev, string targetUser = null, CrossUserRestoreDecision decision = null) =>
            new(runId, image ?? Image(), device, ProvisioningModes.Reimage, Manifest(device),
                targetUser, decision, null);
    }

    // ---- image definitions ----------------------------------------------

    [Fact]
    public void ImageDefinition_Validate_RefusesUnpinnedComponents()
    {
        var img = Image();
        Assert.Null(img.Validate());
        Assert.NotNull((img with { BaseImageHash = "not-a-hash" }).Validate());
        Assert.NotNull((img with { DriverPackHash = "" }).Validate());
        Assert.NotNull((img with { ApplicationPackages = new[] { "widget-no-version" } }).Validate());
        Assert.NotNull((img with { UnattendHash = "zz" }).Validate());
    }

    [Fact]
    public void ImageDefinition_ContentHash_BindsEveryComponent_RoundTrips()
    {
        var img = Image();
        var round = OsImageDefinition.FromCanonicalJson(img.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(img.ContentHash, round.ContentHash);
        // swapping ANY component after authorization changes the hash:
        Assert.NotEqual(img.ContentHash, Image(driverSeed: "drivers-v2").ContentHash);
        Assert.NotEqual(img.ContentHash, (img with { BaseImageHash = H("other-base") }).ContentHash);
        Assert.NotEqual(img.ContentHash, (img with { ApplicationPackages = new[] { "widget@9.9.9" } }).ContentHash);
        Assert.NotEqual(img.ContentHash, (img with { PostProvisionRunbookId = "rb-other" }).ContentHash);
    }

    [Fact]
    public void ImageRepository_SameIdVersionDifferentContent_Conflicts_RevocationRetained()
    {
        var repo = new ImageRepository();
        Assert.Null(repo.Admit(Image()));
        Assert.Null(repo.Admit(Image())); // identical re-admission is idempotent
        var conflict = repo.Admit(Image(driverSeed: "drivers-v2"));
        Assert.NotNull(conflict);
        Assert.Contains("conflict", conflict);
        Assert.True(repo.Revoke("gold", "1.0.0"));
        Assert.True(repo.IsRevoked("gold", "1.0.0"));
        Assert.Single(repo.List()); // revoked definitions stay listed, as a state
    }

    // ---- profile migration (own content type) ----------------------------

    [Fact]
    public void ProfileCapture_SealsVerifies_BoundToSourceDeviceAndUser()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var (pkg, reason) = engine.CaptureAndSeal(Manifest(), FullSource(), T0);
        Assert.NotNull(pkg);
        Assert.Equal(Dev, pkg.SourceDeviceId);
        Assert.Equal(User1, pkg.SourceUserId);
        Assert.Equal(ProfilePackage.ComputeManifestHash(Dev, User1, pkg.Entries), pkg.ManifestHash);
        var (ok, why) = engine.Verify(pkg);
        Assert.True(ok, why);
    }

    [Fact]
    public void ProfileManifest_RefusesTraversal_UnknownCategory_Empty()
    {
        Assert.NotNull(new ProfileCaptureManifest(Dev, User1,
            new[] { new ProfileManifestEntry("../escape.txt", ProfileCategories.Documents) }).Validate());
        Assert.NotNull(new ProfileCaptureManifest(Dev, User1,
            new[] { new ProfileManifestEntry("/abs/path", ProfileCategories.Documents) }).Validate());
        Assert.NotNull(new ProfileCaptureManifest(Dev, User1,
            new[] { new ProfileManifestEntry("x.bin", "everything") }).Validate());
        Assert.NotNull(new ProfileCaptureManifest(Dev, User1, Array.Empty<ProfileManifestEntry>()).Validate());
        Assert.Null(Manifest().Validate());
    }

    [Fact]
    public void ProfileRestore_SameUser_Ok_VerifiedManifestHashReturned()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var (pkg, _) = engine.CaptureAndSeal(Manifest(), FullSource(), T0);
        var (ok, reason, restored, verifiedHash) = engine.Restore(pkg, "dev-9", User1, null);
        Assert.True(ok, reason);
        Assert.Equal(pkg.ManifestHash, verifiedHash);
        Assert.Equal(2, restored.Count);
    }

    // ---- provisioning tokens ----------------------------------------------

    [Fact]
    public void Token_SingleUse_Expiring_MintBound_MismatchDoesNotConsume()
    {
        var tokens = new ProvisioningTokenService();
        var img = Image();
        var code = tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0);
        // binding mismatch refuses WITHOUT consuming — caller may correct:
        Assert.Null(tokens.Redeem(code, img.Id, img.Version, H("different-image"), T0));
        var view = tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0);
        Assert.NotNull(view);
        Assert.Equal(Scope, view.ScopeId);
        // replay of the consumed token refuses:
        Assert.Null(tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0));
        Assert.True(tokens.WasConsumed(code));
        // expiry refuses:
        var code2 = tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0, TimeSpan.FromMinutes(5));
        Assert.Null(tokens.Redeem(code2, img.Id, img.Version, img.ContentHash, T0.AddMinutes(6)));
    }

    // ---- runs --------------------------------------------------------------

    [Fact]
    public void Run_Reimage_HappyPath_Completes_Enrolls_RecordsProfile()
    {
        var rig = new Rig();
        Assert.Null(rig.Images.Admit(Image()));
        var result = rig.Run(Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.Completed, result.State);
        Assert.Equal(1, rig.Imaging.CallCount);
        Assert.Single(rig.Enrollment.Calls);
        Assert.NotNull(result.ProfilePackageId);
        Assert.NotNull(rig.Runner.GetCapturedProfile("run-1"));
    }

    [Fact]
    public void Run_BareMetal_HappyPath_TokenConsumed()
    {
        var rig = new Rig();
        var img = Image();
        Assert.Null(rig.Images.Admit(img));
        var code = rig.Tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0);
        var req = new ProvisioningRunRequest("run-bm", img, Dev, ProvisioningModes.BareMetal,
            null, null, null, code);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.Completed, result.State);
        Assert.True(rig.Tokens.WasConsumed(code));
        Assert.Single(rig.Enrollment.Calls);
    }

    [Fact]
    public void Run_PolicyOff_RefusesBeforeAnything()
    {
        var rig = new Rig();
        Assert.Null(rig.Images.Admit(Image()));
        var result = rig.Run(Rig.ReimageReq(), policy: false);
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    [Fact]
    public void Run_EnvelopeBindingMismatch_Refuses()
    {
        var rig = new Rig();
        Assert.Null(rig.Images.Admit(Image()));
        var req = Rig.ReimageReq();
        // envelope signed for a DIFFERENT device than the request claims:
        var other = Rig.ReimageReq(device: "dev-2");
        var env = rig.EnvelopeFor(other);
        var result = rig.Runner.Run(req, env, new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    [Fact]
    public void Run_DisabledOrUnknownImage_FailsValidationByName()
    {
        var rig = new Rig();
        var disabled = Image() with { Enabled = false };
        // envelope binds the disabled definition; repository holds it too:
        Assert.Null(rig.Images.Admit(disabled));
        var req = new ProvisioningRunRequest("run-d", disabled, Dev, ProvisioningModes.Reimage,
            Manifest(), null, null, null);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedValidation, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    // ---- service level ------------------------------------------------------

    public sealed class ServiceRig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public DevOnlyPassThroughProtector Protector = new();
        public DeviceIdentity Customer;
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;
        public FakeImagingExecutor Imaging = new();
        public FakeEnrollmentSink Enrollment = new();
        public ProvisioningService Service;

        public ServiceRig()
        {
            Customer = new DeviceIdentity(Protector);
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new ProvisioningService(Audit, Policy,
                id => id == Dev ? Facts : null, Signer, Gate, Protector, FullSource(),
                Imaging, Enrollment, null, () => Now);
        }

        public void EnablePolicy() => Policy.AddDocument(new ManagementPolicyDocument(
            "doc-prov", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [ProvisioningPolicyKeys.ProvisioningEnabled] = "true" }, 1));

        public void AdmitAndAccept()
        {
            Assert.True(Service.AdmitImage(Image(), "admin").Allowed);
            Service.RecordDeviceAcceptance(Dev, "endpoint-tech");
        }
    }

    [Fact]
    public void Service_ToggleSeededOff_RunRefused_UntilPolicyExplicitlyEnables()
    {
        var rig = new ServiceRig();
        rig.AdmitAndAccept();
        var refused = rig.Service.RunProvisioning(Rig.ReimageReq(), "admin");
        Assert.Equal(ProvisioningStates.Refused, refused.State);
        Assert.Contains("seeded OFF", refused.Reason);
        Assert.Equal(0, rig.Imaging.CallCount);
        rig.EnablePolicy();
        var done = rig.Service.RunProvisioning(Rig.ReimageReq("run-2"), "admin");
        Assert.Equal(ProvisioningStates.Completed, done.State);
    }

    [Fact]
    public void Service_UnknownDevice_RefusedByName()
    {
        var rig = new ServiceRig();
        rig.EnablePolicy();
        var req = Rig.ReimageReq(device: "ghost-device");
        var result = rig.Service.RunProvisioning(req, "admin");
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Contains("unknown device", result.Reason);
    }

    [Fact]
    public void Service_TokenMint_RefusesUnadmittedOrRevokedImage()
    {
        var rig = new ServiceRig();
        var (code1, v1) = rig.Service.MintProvisioningToken("gold", "1.0.0", Scope, "admin");
        Assert.Null(code1);
        Assert.False(v1.Allowed);
        rig.AdmitAndAccept();
        var (code2, v2) = rig.Service.MintProvisioningToken("gold", "1.0.0", Scope, "admin");
        Assert.NotNull(code2);
        Assert.True(v2.Allowed);
        Assert.True(rig.Service.RevokeImage("gold", "1.0.0", "admin").Allowed);
        var (code3, v3) = rig.Service.MintProvisioningToken("gold", "1.0.0", Scope, "admin");
        Assert.Null(code3);
        Assert.False(v3.Allowed);
    }

    [Fact]
    public void Service_DefaultImagingExecutor_RefusesHonestlyAtApply()
    {
        // A default-constructed service (no imaging executor wired)
        // must refuse at apply by name — never claim an image was written.
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var protector = new DevOnlyPassThroughProtector();
        var customer = new DeviceIdentity(protector);
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var signer = new SignedCommandSigner(customer);
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        var svc = new ProvisioningService(audit, policy, id => id == Dev ? facts : null,
            signer, gate, protector, FullSource());
        Assert.True(svc.AdmitImage(Image(), "admin").Allowed);
        svc.RecordDeviceAcceptance(Dev, "endpoint-tech");
        policy.AddDocument(new ManagementPolicyDocument("doc-prov", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [ProvisioningPolicyKeys.ProvisioningEnabled] = "true" }, 1));
        var result = svc.RunProvisioning(Rig.ReimageReq(), "admin");
        Assert.Equal(ProvisioningStates.FailedApply, result.State);
        Assert.Contains("not wired in this build", result.Reason);
    }
}
