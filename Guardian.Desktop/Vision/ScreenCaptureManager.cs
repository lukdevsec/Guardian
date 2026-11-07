
using Microsoft.Graphics.Canvas;
using Microsoft.UI.Xaml;
using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.Imaging;
using Windows.Foundation;

namespace Guardian.Desktop.Vision;

public sealed class ScreenCaptureManager
{
    public string? LastCapturedWindowTitle { get; private set; }
    public async Task<SoftwareBitmap?> CaptureSingleFrameAsync(
        Window owner,
        CancellationToken cancellationToken = default)
    {
        if (!GraphicsCaptureSession.IsSupported())
        {
            throw new NotSupportedException(
                "Windows Graphics Capture is not supported on this device.");
        }


        // Ask the user to explicitly select a window or display.
        var picker = new GraphicsCapturePicker();

        IntPtr hwnd =
            WinRT.Interop.WindowNative.GetWindowHandle(owner);

        WinRT.Interop.InitializeWithWindow.Initialize(
            picker, hwnd);

        GraphicsCaptureItem? item =
            await picker.PickSingleItemAsync();

        // User cancelled the picker.
        if (item == null)
            return null;
        LastCapturedWindowTitle = item.DisplayName;

        if (item.Size.Width <= 0 || item.Size.Height <= 0)
        {
            throw new InvalidOperationException(
                "Selected capture window has an invalid size.");
        }

        var device = CanvasDevice.GetSharedDevice();

        using var framePool =
            Direct3D11CaptureFramePool.CreateFreeThreaded(
                device,
                DirectXPixelFormat.B8G8R8A8UIntNormalized,
                2,
                item.Size);

        using var session =
            framePool.CreateCaptureSession(item);

        var completion =
            new TaskCompletionSource<SoftwareBitmap>(
                TaskCreationOptions.RunContinuationsAsynchronously);

        Windows.Foundation.TypedEventHandler<
    Direct3D11CaptureFramePool,
    object> frameHandler = async (sender, args) =>
            {
                try
                {
                    using var frame = sender.TryGetNextFrame();

                    if (frame == null)
                        return;

                    SoftwareBitmap bitmap =
                        await SoftwareBitmap.CreateCopyFromSurfaceAsync(
                            frame.Surface,
                            BitmapAlphaMode.Premultiplied);

                    if (!completion.TrySetResult(bitmap))
                    {
                        bitmap.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
            };

        framePool.FrameArrived += frameHandler;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            session.StartCapture();

            // Capture one frame, with a timeout.
            return await completion.Task.WaitAsync(
                TimeSpan.FromSeconds(10),
                cancellationToken);
        }
        finally
        {
            framePool.FrameArrived -= frameHandler;
        }
    }
}
