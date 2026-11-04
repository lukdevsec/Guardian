using Guardian.Service;
using Guardian.Service.IPC;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Guardian Security Service";
});

builder.Services.AddSingleton<TelemetryState>();

builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<PipeServerWorker>();

var host = builder.Build();

await host.RunAsync();