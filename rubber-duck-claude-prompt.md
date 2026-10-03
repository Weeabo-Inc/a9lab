You are a USB protocol and Windows USB-stack expert doing a consult. I do not need code written — I need your reasoning on three timing/tooling observations, and I would rather be told my interpretation is wrong than be agreed with.

SYSTEM: a Rust tool driving an Apple device in USB DFU (firmware-recovery) mode over libusb (rusb 0.9 / libusb 1.0.27) on Windows 11. The device node is bound to the libusbK driver (3.1.0.0). Negotiated speed is HIGH (480 Mbit/s), attached to a USB 3.0 root hub (USB\ROOT_HUB30), interface 0 claimed. We record per-transfer status and microsecond timing in a JSONL trace, and we capture the wire with USBPcap 1.5.4.

OBSERVATION 1 — a control request whose STALL arrives late.
We send an intentionally invalid control request: bmRequestType=0x00, bRequest=0x00, wValue=0, wIndex=0, wLength=1280, with a 1280-byte zero-filled OUT data stage. Across thousands of attempts the device answers non-uniformly:
  - usually: no answer within our timeout (libusb returns LIBUSB_ERROR_TIMEOUT, -7)
  - rarely: a genuine STALL (libusb returns LIBUSB_ERROR_PIPE, -9)
  - every STALL we have ever recorded arrives at 21.4-37 ms; none below 21 ms
A USBPcap decode of one STALL case shows the completion IRP carrying USBD_STATUS 0xC0000004 (USBD_STATUS_STALL_PID) 23.0 ms after submit. A different, successful 16-byte OUT DOWNLOAD in the same capture completes with dataLength=0.

QUESTIONS:
(a) Is there any host-side or Windows-USB-stack reason a STALL handshake would be *reported* ~23 ms late rather than as soon as it arrives? Could the completion be delayed by the driver, the hub driver, a port-state machine, or the capture layer?
(b) Can libusbK, WinUSB, or USBPcap manufacture or delay a STALL_PID completion in that way? Is STALL_PID at 23 ms strong evidence that the device itself chose to stall at 23 ms, or can the host fabricate that status?
(c) Is a consistent ~23 ms with no spread more consistent with a device-side watchdog/state-machine timer, or with some mundane host behaviour (retry, port reset, error recovery, timer coalescing) that I have not thought of?
(d) What single measurement would definitively separate "the device stalled at t=23 ms" from "the host took 23 ms to notice a stall that happened earlier"?

OBSERVATION 2 — partial byte counts on a cancelled control transfer.
Our tool deliberately sets the libusb transfer timeout to 0 on asynchronous control transfers, on the theory that with no second terminator a cancelled transfer reports a real partial data-stage byte count rather than being relabelled as a timeout.
(a) On Windows with libusbK, does a CANCELLED control transfer report a partial byte count, or 0 regardless? Where in the stack would that number come from?
(b) USBPcap's completion records show dataLength=0 for OUT transfers even when they succeed, so we concluded USBPcap cannot tell us what the *device* consumed. Is there ANY Windows API or capture technique that can report, for a cancelled control OUT transfer, how many bytes the device actually accepted? (IoStatus.Information via a filter driver? ETW / USB event tracing? WPP tracing? A different USBPcap mode?)
(c) We plan to test this by aborting an IN control transfer (a GET_DESCRIPTOR read), reasoning that for IN transfers the completion record's dataLength IS the transferred count. Is that reasoning correct on Windows, and would an aborted IN read be a valid probe of the OUT behaviour?

OBSERVATION 3 — a true sub-tick deadline for a synchronous control transfer.
Windows cannot honour sub-tick waits: a 1 ms WaitForMultipleObjects (which is what libusb's Windows event loop uses internally) blocks for ~15.6 ms; we measured 1/2/3/4/5/10/15 ms all returning at ~15.5 ms, and 16 ms at ~30.9 ms. timeBeginPeriod(1) returned TIMERR_NOERROR with a reported 1.000 ms resolution and did NOT help. We fixed our own event loop by polling with a zero timeout against an Instant deadline (verified effective 1.000/2.000/4.000/5.000 ms).
(a) Is there a supported way to give a control transfer a true sub-tick deadline without reimplementing the transfer loop — e.g. does WinUSB or libusbK expose a per-transfer timeout that the kernel honours, or a way to have the URB complete on a timer?
(b) If we convert this synchronous control transfer to our async submit/cancel path, what changes about the reported status for the "device never answered" case, and how do we keep it distinguishable from a genuine STALL? (Our callers key on libusb's -7 vs -9.)
(c) Any pitfalls in issuing a cancel on a control transfer whose data stage may not have started — e.g. does the cancel race the setup stage and produce a misleading completion status?

Answer each question with your reasoning, label confidence (high/medium/low), and where you are unsure say what measurement would settle it. Be concrete and skeptical. Do not write code; do not modify any file.