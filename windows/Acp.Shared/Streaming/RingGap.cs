namespace Acp.Shared.Streaming;

/// <summary>
/// BD-WIN-AGENT F12 (stream leg): the ring-gap decision. The stream
/// ring holds a bounded window of frames; a viewer whose afterSeq
/// has fallen behind the ring's OLDEST frame can never be made whole
/// by the next delta — it needs a gap signal plus a fresh keyframe.
/// Before this, GetFrame silently returned the oldest surviving
/// delta and the viewer decoded garbage (or nothing) with no signal.
/// Pure arithmetic so the test project can pin it.
/// </summary>
public static class RingGap
{
    /// <summary>True when the requester has missed frames that have
    /// already left the ring: frames exist, the ring's oldest frame
    /// is newer than the very next frame the requester needs, and
    /// the requester is not already at/past the newest frame.</summary>
    public static bool HasGap(long afterSeq, long oldestSeqInRing, long newestSeqInRing)
    {
        if (newestSeqInRing <= 0 || oldestSeqInRing <= 0) return false; // nothing encoded yet
        if (afterSeq >= newestSeqInRing) return false;                 // caught up: an empty answer is honest
        return oldestSeqInRing > afterSeq + 1;                          // the next needed frame is gone
    }
}
