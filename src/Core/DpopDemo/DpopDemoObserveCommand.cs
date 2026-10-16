using System.CommandLine;

namespace GitCredentialManager.DpopDemo;

internal sealed class DpopDemoObserveCommand : Command
{
    internal DpopDemoObserveCommand(ICommandContext context, string configPath)
        : base("observe", "[Git DPoP demo] Observe the selected helper's HTTP attempt")
    {
        IsHidden = true;
        this.SetHandler(() => DpopDemoCommand.Execute(context, "observe", configPath));
    }
}
