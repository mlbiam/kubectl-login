/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	outokens "github.com/tremolosecurity/openunison-cli/pkg"
)

// oidcCmd represents the oidc command
var oidcCmd = &cobra.Command{
	Use:   "oidc",
	Short: "client-go sdk exec plugin for OIDC",
	Long:  `This command returns a JSON object that can be used as an exec plugin for Kubernetes. based on the oidc information from OpenUnison.  This command takes one argument, the path to the JSON document that contains the OIDC information.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("Error: expected a single argument for the path to the JSON file")
			os.Exit(1)
		}

		path := args[0]
		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Printf("Error: file does not exist at path '%s'\n", path)
			os.Exit(1)
		}

		oidcSession, err := outokens.LoadSessionFromFile(path)
		if err != nil {
			fmt.Printf("Error loading OIDC session: %v\n", err)
			os.Exit(1)
		}
		if oidcSession.RefreshSession(context.TODO()) {
			_, err = outokens.SaveSessionToTempFile(oidcSession, path)
			if err != nil {
				fmt.Printf("Error saving OIDC session: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("OIDC session saved to %s\n", path)
		}

		execCredential, err := outokens.GenerateExecCredential(oidcSession.IDToken)
		if err != nil {
			fmt.Printf("Error generating exec credential: %v\n", err)
			os.Exit(1)
		}
		execCredentialJSON, err := outokens.MarshalExecCredential(execCredential)
		if err != nil {
			fmt.Printf("Error marshaling exec credential: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(execCredentialJSON))

	},
}

func init() {
	rootCmd.AddCommand(oidcCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// oidcCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// oidcCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
