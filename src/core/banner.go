package core

import (
	"fmt"

	"github.com/fatih/color"
)

const (
	VERSION = "3.3.0"
)

// putAsciiArt renders colored blocks: R=red, r=dark red, W=white, K=black,
// Y=gold, M=maroon, .=transparent
func putAsciiArt(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "R":
			color.Set(color.BgRed, color.FgHiWhite)
			d = " "
		case "r":
			color.Set(color.BgHiRed)
			d = " "
		case "W":
			color.Set(color.BgWhite)
			d = " "
		case "K":
			color.Set(color.BgBlack, color.FgHiWhite)
			d = " "
		case "Y":
			color.Set(color.BgYellow, color.FgBlack)
			d = " "
		case "M":
			color.Set(color.BgHiBlack, color.FgHiWhite)
			d = " "
		case ".":
			color.Unset()
			d = " "
		case "\n":
			color.Unset()
		default:
			color.Unset()
		}
		fmt.Print(d)
	}
	color.Unset()
}

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

// Banner prints the RedPhish joker banner on startup.
func Banner() {
	fmt.Println()

	// Jester hat (3 horns + gold bells)
	putAsciiArt("......__Y__.........__Y__.........__Y__.....\n")
	putAsciiArt("....__/...\\__Y_____/...\\__Y_____/...\\_....\n")
	putAsciiArt(".../..RRRR......RRRR.......RRRR.....\\...\n")
	putAsciiArt("../..RRRRr.....RRRRr.......RRRRr......\\..\n")
	putAsciiArt("./..RRRRRR....RRRRRR......RRRRRR.......\\.\n")
	putAsciiArt("./.RRRRRRR...RRRRRRR.....RRRRRRR........\n")
	putAsciiArt("..RRRRRRRRR.RRRRRRRRR..RRRRRRRRR........\n")
	putAsciiArt("..RRRRRRRRRRRRRRRRRRRRRRRRRRRRRR........\n")

	// Face (white with features)
	putAsciiArt("..RRWWWWWWWWWWWWWWWWWWWWWWWWWWRR........\n")
	putAsciiArt("..RWWKKWWWWWWWKKKWWWWWWWKKWWWR..........\n")
	putAsciiArt("..RWWKKWWWWWWWKKKWWWWWWWKKWWWR..........\n")
	putAsciiArt("..RWWWWWWWWWWKKKKWWWWWWWWWWWR...........\n")
	putAsciiArt("..RWWWWWWWWWWKKKKWWWWWWWWWWWR...........\n")
	putAsciiArt("..RWWKKKKKKKKKKKKKKKKKKKKKWWWR...........\n")
	putAsciiArt("..RWWKYYKYYKYYKYYKYYKYYKYYKWWWR..........\n")
	putAsciiArt("..RWWKKKKKKKKKKKKKKKKKKKKKWWWR...........\n")
	putAsciiArt("..RRWWWWWWWWWWWWWWWWWWWWWWWRR............\n")

	// Collar (red spikes)
	putAsciiArt("..RRRRRRRRRRRRRRRRRRRRRRRRRRRR............\n")
	putAsciiArt(".RRrRRrRRr..RRrRRrRRr..RRrRRrRRr.........\n")
	putAsciiArt("RRr.RRr.RRr.RRr.RRr.RRr.RRr.RRr.RRr......\n")

	// REDPHISH wordmark
	fmt.Println()
	printRedText("  ██████╗ ███████╗███████╗ █████╗ ██╗  ██╗██████╗ ██╗     ███████╗\n")
	printRedText(" ██╔══██╗██╔════╝██╔════╝██╔══██╗██║ ██╔╝██╔══██╗██║     ██╔════╝\n")
	printRedText(" ██████╔╝█████╗  █████╗  ███████║█████╔╝ ██████╔╝██║     ███████╗\n")
	printRedText(" ██╔══██╗██╔══╝  ██╔══╝  ██╔══██║██╔═██╗ ██╔══██╗██║     ╚════██║\n")
	printRedText(" ██║  ██║███████╗███████╗██║  ██║██║  ██╗██████╔╝███████╗███████║\n")
	printGoldText(" ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝\n")

	fmt.Println()
	printVersion()
	fmt.Println()
	fmt.Println()
}
