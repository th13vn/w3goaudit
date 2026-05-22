package main

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for w3goaudit.

To enable completions:

  Bash:
    source <(w3goaudit completion bash)

    # Or save to a file and source in .bashrc:
    w3goaudit completion bash > ~/.w3goaudit-completion.bash
    echo 'source ~/.w3goaudit-completion.bash' >> ~/.bashrc

  Zsh:
    w3goaudit completion zsh > "${fpath[1]}/_w3goaudit"

    # Or if shell completion is not enabled:
    echo "autoload -U compinit; compinit" >> ~/.zshrc

  Fish:
    w3goaudit completion fish | source

    # Or save:
    w3goaudit completion fish > ~/.config/fish/completions/w3goaudit.fish

  PowerShell:
    w3goaudit completion powershell | Out-String | Invoke-Expression`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}
