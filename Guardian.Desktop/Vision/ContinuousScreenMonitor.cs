
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Graphics.Canvas;
using Microsoft.UI.Xaml;

using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.Imaging;

namespace Guardian.Desktop.Vision;

public sealed class ContinuousScreenMonitor : IAsyncDisposable
{
    private Direct3D11CaptureFramePool? _pool;
    private GraphicsCaptureSession? _session;
    private GraphicsCaptureItem? _item;
    private CanvasDevice? _device;

    private CancellationTokenSource? _cts;
    private Task _processingTask = Task.CompletedTask;

    private Func<SoftwareBitmap, Task>? _analyzeFrame;

    private int _processing;
    private long _lastAnalysisTimestamp;
    private long _lastFrameUtcTicks;
    private long _lastCompletedUtcTicks;

    private readonly TimeSpan _interval =
        TimeSpan.FromSeconds(5);

    public bool IsRunning { get; private set; }

    public string? SelectedWindowTitle { get; private set; }

    public DateTime? LastFrameReceivedUtc =>
        ReadUtcTime(ref _lastFrameUtcTicks);

    public DateTime? LastAnalysisCompletedUtc =>
        ReadUtcTime(ref _lastCompletedUtcTicks);

    private static DateTime? ReadUtcTime(ref long ticks)
    {
        long value = Interlocked.Read(ref ticks);

        return value == 0
            ? null
            : new DateTime(value, DateTimeKind.Utc);
    }

    public async Task<bool> StartAsync(
        Window owner,
        Func<SoftwareBitmap, Task> analyzeFrame)
    {
        if (IsRunning)
            return true;

        if (!GraphicsCaptureSession.IsSupported())
        {
            throw new NotSupportedException(
                "Windows Graphics Capture is unavailable.");
        }

        var picker = new GraphicsCapturePicker();

        IntPtr hwnd =
            WinRT.Interop.WindowNative.GetWindowHandle(owner);

        WinRT.Interop.InitializeWithWindow.Initialize(
            picker, hwnd);

        var item = await picker.PickSingleItemAsync();

        if (item == null)
            return false;

        if (item.Size.Width <= 0 || item.Size.Height <= 0)
        {
            throw new InvalidOperationException(
                "Invalid capture target dimensions.");
        }

        try
        {
            _device = CanvasDevice.GetSharedDevice();

            _pool = Direct3D11CaptureFramePool.CreateFreeThreaded(
                _device,
                DirectXPixelFormat.B8G8R8A8UIntNormalized,
                2,
                item.Size);

            _session = _pool.CreateCaptureSession(item);
            _item = item;

            _cts = new CancellationTokenSource();

            _analyzeFrame = analyzeFrame;
            SelectedWindowTitle = item.DisplayName;

            _processingTask = Task.CompletedTask;

            Interlocked.Exchange(ref _processing, 0);
            Interlocked.Exchange(ref _lastAnalysisTimestamp, 0);
            Interlocked.Exchange(ref _lastFrameUtcTicks, 0);
            Interlocked.Exchange(ref _lastCompletedUtcTicks, 0);

            _pool.FrameArrived += OnFrameArrived;
            _item.Closed += OnCaptureClosed;

            IsRunning = true;

            _session.StartCapture();

            Debug.WriteLine(
                $"Guardian capture started: {SelectedWindowTitle}");

            return true;
        }
        catch
        {
            await StopAsync();
            throw;
        }
    }

    private void OnCaptureClosed(
        GraphicsCaptureItem sender,
        object args)
    {
        Debug.WriteLine(
            "Guardian: selected capture window was closed.");

        _ = StopAsync();
    }

    private void OnFrameArrived(
        Direct3D11CaptureFramePool sender,
        object args)
    {
        Direct3D11CaptureFrame? frame = null;

        try
        {
            // IMPORTANT:
            // Always retrieve the new frame, even when OCR
            // is currently busy. Otherwise buffers can fill
            // and the capture pipeline may stop advancing.

            frame = sender.TryGetNextFrame();

            if (frame == null)
                return;

            Interlocked.Exchange(
                ref _lastFrameUtcTicks,
                DateTime.UtcNow.Ticks);

            if (!IsRunning ||
                _cts?.IsCancellationRequested != false)
            {
                return;
            }

            // One analysis at a time.
            // Busy frames will be discarded below.
            if (Interlocked.CompareExchange(
                    ref _processing, 1, 0) != 0)
            {
                return;
            }

            long now = Stopwatch.GetTimestamp();

            long previous = Interlocked.Read(
                ref _lastAnalysisTimestamp);

            double elapsed = previous == 0
                ? double.MaxValue
                : (now - previous) /
                  (double)Stopwatch.Frequency;

            if (elapsed < _interval.TotalSeconds)
            {
                Interlocked.Exchange(ref _processing, 0);
                return;
            }

            Interlocked.Exchange(
                ref _lastAnalysisTimestamp,
                now);

            Debug.WriteLine(
                $"Guardian frame accepted: {DateTime.Now:HH:mm:ss}");

            // Transfer ownership to ProcessFrameAsync.
            var acceptedFrame = frame;
            frame = null;

            try
            {
                _processingTask = ProcessFrameAsync(
                    acceptedFrame,
                    _cts.Token);
            }
            catch
            {
                acceptedFrame.Dispose();

                Interlocked.Exchange(ref _processing, 0);
                throw;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian FrameArrived error: {ex}");
        }
        finally
        {
            // Frames not selected for analysis are returned
            // immediately to the capture frame pool.
            frame?.Dispose();
        }
    }

    private async Task ProcessFrameAsync(
        Direct3D11CaptureFrame frame,
        CancellationToken token)
    {
        try
        {
            SoftwareBitmap bitmap;

            // Copy the frame and release it BEFORE OCR.
            // This is important for continuous capture.
            using (frame)
            {
                bitmap =
                    await SoftwareBitmap.CreateCopyFromSurfaceAsync(
                        frame.Surface,
                        BitmapAlphaMode.Premultiplied);
            }

            using (bitmap)
            {
                token.ThrowIfCancellationRequested();

                var analyzer = _analyzeFrame;

                if (analyzer != null)
                {
                    await analyzer(bitmap);
                }
            }

            Interlocked.Exchange(
                ref _lastCompletedUtcTicks,
                DateTime.UtcNow.Ticks);

            Debug.WriteLine(
                $"Guardian analysis completed: {DateTime.Now:HH:mm:ss}");
        }
        catch (OperationCanceledException)
        {
            Debug.WriteLine(
                "Guardian analysis cancelled.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian continuous analysis failed: {ex}");
        }
        finally
        {
            Interlocked.Exchange(ref _processing, 0);
        }
    }

    public async Task StopAsync()
    {
        IsRunning = false;

        _cts?.Cancel();

        if (_pool != null)
            _pool.FrameArrived -= OnFrameArrived;

        if (_item != null)
            _item.Closed -= OnCaptureClosed;

        _session?.Dispose();
        _session = null;

        try
        {
            await _processingTask;
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Guardian shutdown warning: {ex.Message}");
        }

        _pool?.Dispose();
        _pool = null;

        _item = null;
        _device = null;

        _cts?.Dispose();
        _cts = null;

        _analyzeFrame = null;
        SelectedWindowTitle = null;

        Debug.WriteLine("Guardian capture stopped.");
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
