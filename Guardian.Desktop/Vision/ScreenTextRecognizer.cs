
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using RapidOcrNet;

using Windows.Graphics.Imaging;
using Windows.Storage;

namespace Guardian.Desktop.Vision;

public sealed class ScreenTextRecognizer
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    private RapidOcr? _engine;

    private static string ModelDirectory =>
        Path.Combine(
            AppContext.BaseDirectory,
            "models",
            "v5");

    private void InitializeEngine()
    {
        string directory = ModelDirectory;

        string detPath = Path.Combine(
            directory,
            "ch_PP-OCRv5_mobile_det.onnx");

        string clsPath = Path.Combine(
            directory,
            "ch_PP-LCNet_x0_25_textline_ori_cls_mobile.onnx");

        string recPath = Path.Combine(
            directory,
            "latin_PP-OCRv5_rec_mobile_infer.onnx");

        string keysPath = Path.Combine(
            directory,
            "ppocrv5_latin_dict.txt");

        string[] requiredFiles =
        {
            detPath,
            clsPath,
            recPath,
            keysPath
        };

        foreach (string path in requiredFiles)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException(
                    $"Guardian OCR model is missing: {path}",
                    path);
            }
        }

        var engine = new RapidOcr();

        engine.InitModels(
            detPath: detPath,
            clsPath: clsPath,
            recPath: recPath,
            keysPath: keysPath);

        _engine = engine;

        Debug.WriteLine(
            $"Guardian OCR initialized from: {directory}");
    }

    public async Task<string> RecognizeAsync(
        SoftwareBitmap source,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        await _gate.WaitAsync(cancellationToken);

        StorageFile? temporaryImage = null;

        try
        {
            // Initialize OCR models only once.
            if (_engine == null)
            {
                await Task.Run(
                    InitializeEngine,
                    cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();

            // Use a normal per-user temporary directory.
            // ApplicationData.Current is not reliable for full-trust desktop processes.
            string tempDirectory = Path.Combine(
                Path.GetTempPath(),
                "Guardian",
                "OCR");

            Directory.CreateDirectory(tempDirectory);

            StorageFolder tempFolder =
                await StorageFolder.GetFolderFromPathAsync(tempDirectory);

            temporaryImage = await tempFolder.CreateFileAsync(
                $"guardian-ocr-{Guid.NewGuid():N}.png",
                CreationCollisionOption.GenerateUniqueName);

            // Encode captured image.
            using (var stream = await temporaryImage.OpenAsync(
                FileAccessMode.ReadWrite))
            {
                var encoder = await BitmapEncoder.CreateAsync(
                    BitmapEncoder.PngEncoderId,
                    stream);

                encoder.SetSoftwareBitmap(source);

                await encoder.FlushAsync();
            }

            cancellationToken.ThrowIfCancellationRequested();

            Debug.WriteLine(
                "Guardian OCR inference started.");

            // Run local ONNX inference.
            var result = await _engine!.DetectAsync(
                temporaryImage.Path,
                RapidOcrOptions.Default,
                cancellationToken: cancellationToken);

            string text = result.StrRes ?? string.Empty;

            Debug.WriteLine(
                $"Guardian OCR completed. Characters: {text.Length}");

            return text;
        }
        finally
        {
            // Remove temporary screenshot.
            if (temporaryImage != null)
            {
                try
                {
                    await temporaryImage.DeleteAsync(
                        StorageDeleteOption.PermanentDelete);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(
                        $"OCR temporary cleanup: {ex.Message}");
                }
            }

            _gate.Release();
        }
    }
}
