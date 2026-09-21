package core

import (
	"fmt"

	"github.com/fatih/color"
)

const (
	VERSION = "3.3.0"
)

func printRedText(s string) {
	c := color.New(color.FgHiRed, color.Bold)
	fmt.Fprintf(color.Output, "%s", c.Sprintf("%s", s))
}

func printGoldText(s string) {
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

	printRedText(" ███████╗██████╗ ██╗  ██╗███████╗██╗  ██╗███████╗ █████╗ \n")
	printRedText(" ██╔════╝██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔════╝██╔══██╗\n")
	printRedText(" █████╗  ██████╔╝█████╔╝ █████╗  ███████║█████╗  ███████║\n")
	printRedText(" ██╔══╝  ██╔══██╗██╔═██╗ ██╔══╝  ██╔══██║██╔══╝  ╚════██║\n")
	printRedText(" ███████╗██║  ██║██║  ██╗███████╗██║  ██║███████╗███████║\n")
	printGoldText(" ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝\n")

	fmt.Println()
	printVersion()
	fmt.Println()
	fmt.Println()
}
