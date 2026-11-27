using DeskGuest.Shared.Streaming;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The streaming encode ladder, walked once at stream start
/// (BUILD-PROGRAMME fallback-ladder law, first named ladder):
///   1. Media Foundation hardware H.264
///   2. Media Foundation software H.264
///   3. Bundled software encoder (OpenH264)
/// Descent is automatic and the winning rung's name + hardware
/// flag are what the stream reports — a machine on a fallback is
/// told so, in those words, in the stream_start result, the
/// stats, and every frame header. The choice is sticky for the
/// stream's lifetime: a ladder that never re-decides mid-stream
/// cannot flap, and there is no break to make before — the old
/// encoder is only disposed when the stream stops.
/// If every rung fails, the error names each rung and its reason.
/// </summary>
internal static class StreamEncoderLadder
{
    public static bool TryCreate(int width, int height, int fps, int bitrateBps,
        out IH264StreamEncoder? encoder, out string error)
    {
        var rungs = new (string Name, Func<(bool Ok, IH264StreamEncoder? Value, string Error)> Attempt)[]
        {
            ("Media Foundation hardware", () =>
            {
                var ok = H264Encoder.TryCreatePass(hardware: true, width, height, fps, bitrateBps, out var enc, out var err);
                return (ok, (IH264StreamEncoder?)enc, err);
            }),
            ("Media Foundation software", () =>
            {
                var ok = H264Encoder.TryCreatePass(hardware: false, width, height, fps, bitrateBps, out var enc, out var err);
                return (ok, (IH264StreamEncoder?)enc, err);
            }),
            ("Bundled software (OpenH264)", () =>
            {
                var ok = OpenH264Encoder.TryCreate(width, height, fps, bitrateBps, out var enc, out var err);
                return (ok, (IH264StreamEncoder?)enc, err);
            }),
        };
        return FallbackLadder.TryInOrder(rungs, out encoder, out error);
    }
}
