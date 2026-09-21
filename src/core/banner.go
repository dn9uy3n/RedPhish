package core

import (
	"fmt"

	"github.com/fatih/color"
)

const (
	VERSION = "3.3.0"
)

func printRed(s string) {
	c := color.New(color.FgHiRed, color.Bold)
	fmt.Fprintf(color.Output, "%s", c.Sprintf("%s", s))
}

func printGold(s string) {
	c := color.New(color.FgYellow)
	fmt.Fprintf(color.Output, "%s", c.Sprintf("%s", s))
}

func printVersion() {
	verClr := color.New(color.FgGreen)
	nameClr := color.New(color.FgHiWhite)
	txtClr := color.New(color.FgHiBlack)
	txt := txtClr.Sprintf("        fork of evilginx2 CE (") + nameClr.Sprintf("@mrgretzky") +
		txtClr.Sprintf(")") + txtClr.Sprintf("  version ") + verClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

// Banner prints the RedPhish text-art banner on startup.
func Banner() {
	fmt.Println()
	fmt.Println()

	printRed(" _____  ______ _____  _____  _    _ _____  _____ _    _ \n")
	printRed("|  __ \\|  ____|  __ \\|  __ \\| |  | |_   _|/ ____| |  | |\n")
	printRed("| |__) | |__  | |  | | |__) | |__| | | | | (___ | |__| |\n")
	printRed("|  _  /|  __| | |  | |  ___/|  __  | | |  \\___ \\|  __  |\n")
	printRed("| | \\ \\| |____| |__| | |    | |  | |_| |_ ____) | |  | |\n")
	printGold("|_|  \\_\\______|_____/|_|    |_|  |_|_____|_____/|_|  |_|\n")

	fmt.Println()
	printVersion()
	fmt.Println()
	fmt.Println()
}
