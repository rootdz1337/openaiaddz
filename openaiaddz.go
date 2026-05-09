package main

import (
	"context"
	"flag"
	"fmt"
	"log"
//	"os"
	"strings"
	
	openai "github.com/sashabaranov/go-openai"
	"github.com/go-ldap/ldap/v3"
)

// AD Recon configuration
type ADConfig struct {
	LDAPServer   string
	BindUser     string
	BindPassword string
	BaseDN       string
}

// AD Recon results
type ADReconResult struct {
	Users                 []string
	DomainAdmins          []string
	KerberoastableUsers   map[string][]string
	UnconstrainedDelegation []string
	Computers             []string
}

func main() {
	// Command line flags
	mode := flag.String("mode", "openai", "Mode: 'openai', 'ad-recon', or 'all'")
	ldapServer := flag.String("ldap", "ldap://dc.target.local:389", "LDAP server URL")
	bindUser := flag.String("bind-user", "", "LDAP bind username")
	bindPass := flag.String("bind-pass", "", "LDAP bind password")
	baseDN := flag.String("base-dn", "dc=target,dc=local", "LDAP base DN")
	openaiToken := flag.String("openai-token", "", "OpenAI API token")
	query := flag.String("query", "Hello!", "Query for OpenAI")
	
	flag.Parse()

	switch *mode {
	case "openai":
		if *openaiToken == "" {
			log.Fatal("OpenAI token required for openai mode")
		}
		runOpenAI(*openaiToken, *query)
		
	case "ad-recon":
		config := ADConfig{
			LDAPServer:   *ldapServer,
			BindUser:     *bindUser,
			BindPassword: *bindPass,
			BaseDN:       *baseDN,
		}
		runADRecon(config)
		
	case "all":
		if *openaiToken == "" {
			log.Fatal("OpenAI token required for all mode")
		}
		config := ADConfig{
			LDAPServer:   *ldapServer,
			BindUser:     *bindUser,
			BindPassword: *bindPass,
			BaseDN:       *baseDN,
		}
		
		// Run AD recon first
		fmt.Println("=== ACTIVE DIRECTORY RECONNAISSANCE ===\n")
		results := runADRecon(config)
		
		// Then use OpenAI to analyze results
		fmt.Println("\n=== OPENAI ANALYSIS OF AD RESULTS ===\n")
		analysisPrompt := buildAnalysisPrompt(results)
		runOpenAIWithContext(*openaiToken, analysisPrompt)
	}
}

// Original OpenAI function
func runOpenAI(token, query string) {
	client := openai.NewClient(token)
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: query,
				},
			},
		},
	)

	if err != nil {
		fmt.Printf("ChatCompletion error: %v\n", err)
		return
	}

	fmt.Println(resp.Choices[0].Message.Content)
}

// OpenAI with custom context
func runOpenAIWithContext(token, prompt string) {
	client := openai.NewClient(token)
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		fmt.Printf("ChatCompletion error: %v\n", err)
		return
	}

	fmt.Println(resp.Choices[0].Message.Content)
}

// Main AD Recon function
func runADRecon(config ADConfig) ADReconResult {
	results := ADReconResult{
		KerberoastableUsers: make(map[string][]string),
	}
	
	// Connect to LDAP
	l, err := ldap.DialURL(config.LDAPServer)
	if err != nil {
		log.Fatalf("Failed to connect to LDAP: %v", err)
	}
	defer l.Close()
	
	// Bind to LDAP
	if config.BindUser != "" && config.BindPassword != "" {
		err = l.Bind(config.BindUser, config.BindPassword)
	} else {
		// Anonymous bind
		err = l.Bind("", "")
	}
	if err != nil {
		log.Fatalf("LDAP bind failed: %v", err)
	}
	
	fmt.Printf("[+] Connected to %s\n", config.LDAPServer)
	
	// Run all enumeration functions
	results.Users = enumerateUsers(l, config.BaseDN)
	results.DomainAdmins = findDomainAdmins(l, config.BaseDN)
	results.KerberoastableUsers = findKerberoastableUsers(l, config.BaseDN)
	results.UnconstrainedDelegation = findUnconstrainedDelegation(l, config.BaseDN)
	results.Computers = enumerateComputers(l, config.BaseDN)
	
	// Print results
	printResults(results)
	
	return results
}

func enumerateUsers(l *ldap.Conn, baseDN string) []string {
	fmt.Println("\n[*] Enumerating enabled users...")
	var users []string
	
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "userPrincipalName", "mail", "description"},
		nil,
	)
	
	result, err := l.Search(searchReq)
	if err != nil {
		log.Printf("User enumeration failed: %v", err)
		return users
	}
	
	for _, entry := range result.Entries {
		username := entry.GetAttributeValue("sAMAccountName")
		users = append(users, username)
		fmt.Printf("  [+] User: %s", username)
		
		if mail := entry.GetAttributeValue("mail"); mail != "" {
			fmt.Printf(" (%s)", mail)
		}
		if desc := entry.GetAttributeValue("description"); desc != "" {
			fmt.Printf(" - %s", desc)
		}
		fmt.Println()
	}
	
	fmt.Printf("  Total users found: %d\n", len(users))
	return users
}

func findDomainAdmins(l *ldap.Conn, baseDN string) []string {
	fmt.Println("\n[*] Looking for Domain Admins...")
	var admins []string
	
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,%s))", baseDN),
		[]string{"sAMAccountName"},
		nil,
	)
	
	result, err := l.Search(searchReq)
	if err != nil {
		log.Printf("Domain admin search failed: %v", err)
		return admins
	}
	
	for _, entry := range result.Entries {
		username := entry.GetAttributeValue("sAMAccountName")
		admins = append(admins, username)
		fmt.Printf("  [ADMIN] %s\n", username)
	}
	
	return admins
}

func findKerberoastableUsers(l *ldap.Conn, baseDN string) map[string][]string {
	fmt.Println("\n[*] Finding Kerberoastable users (have SPNs)...")
	kerberoastable := make(map[string][]string)
	
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=user)(servicePrincipalName=*))",
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	)
	
	result, err := l.Search(searchReq)
	if err != nil {
		log.Printf("Kerberoastable search failed: %v", err)
		return kerberoastable
	}
	
	for _, entry := range result.Entries {
		username := entry.GetAttributeValue("sAMAccountName")
		spns := entry.GetAttributeValues("servicePrincipalName")
		kerberoastable[username] = spns
		
		fmt.Printf("  [KERBEROAST] %s\n", username)
		for _, spn := range spns {
			fmt.Printf("      SPN: %s\n", spn)
		}
	}
	
	return kerberoastable
}

func findUnconstrainedDelegation(l *ldap.Conn, baseDN string) []string {
	fmt.Println("\n[*] Checking for unconstrained delegation...")
	var delegations []string
	
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		[]string{"dNSHostName", "name"},
		nil,
	)
	
	result, err := l.Search(searchReq)
	if err != nil {
		log.Printf("Delegation check failed: %v", err)
		return delegations
	}
	
	for _, entry := range result.Entries {
		computer := entry.GetAttributeValue("dNSHostName")
		if computer == "" {
			computer = entry.GetAttributeValue("name")
		}
		delegations = append(delegations, computer)
		fmt.Printf("  [UNCONSTRAINED] %s\n", computer)
	}
	
	return delegations
}

func enumerateComputers(l *ldap.Conn, baseDN string) []string {
	fmt.Println("\n[*] Enumerating computers...")
	var computers []string
	
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=computer)",
		[]string{"dNSHostName", "operatingSystem"},
		nil,
	)
	
	result, err := l.Search(searchReq)
	if err != nil {
		log.Printf("Computer enumeration failed: %v", err)
		return computers
	}
	
	for _, entry := range result.Entries {
		computer := entry.GetAttributeValue("dNSHostName")
		computers = append(computers, computer)
		fmt.Printf("  [COMPUTER] %s", computer)
		if os := entry.GetAttributeValue("operatingSystem"); os != "" {
			fmt.Printf(" (%s)", os)
		}
		fmt.Println()
	}
	
	fmt.Printf("  Total computers found: %d\n", len(computers))
	return computers
}

func printResults(results ADReconResult) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("AD RECONNAISSANCE SUMMARY")
	fmt.Println(strings.Repeat("=", 50))
	
	fmt.Printf("\n📊 Users Found: %d\n", len(results.Users))
	fmt.Printf("👑 Domain Admins: %d\n", len(results.DomainAdmins))
	fmt.Printf("🎯 Kerberoastable Accounts: %d\n", len(results.KerberoastableUsers))
	fmt.Printf("🖥️  Computers: %d\n", len(results.Computers))
	fmt.Printf("🔓 Unconstrained Delegation: %d\n", len(results.UnconstrainedDelegation))
	
	if len(results.KerberoastableUsers) > 0 {
		fmt.Println("\n💡 RECOMMENDATION: Extract and crack Kerberos tickets:")
		fmt.Println("   sudo impacket-GetUserSPNs -request -dc-ip <DC_IP> target.local/username")
	}
	
	if len(results.UnconstrainedDelegation) > 0 {
		fmt.Println("\n⚠️  WARNING: Unconstrained delegation detected - privilege escalation risk!")
	}
}

func buildAnalysisPrompt(results ADReconResult) string {
	prompt := fmt.Sprintf(`As a cybersecurity expert, analyze these Active Directory reconnaissance results:

FINDINGS:
- Total Users: %d
- Domain Admins: %d
- Kerberoastable Accounts: %d
- Computers: %d
- Systems with Unconstrained Delegation: %d

Based on these findings, please provide:
1. Security risk assessment
2. Prioritized recommendations for remediation
3. Most critical vulnerabilities to address first

Specific Kerberoastable accounts found: %v

Specific unconstrained delegation: %v

Please provide actionable security advice.`,
		len(results.Users),
		len(results.DomainAdmins),
		len(results.KerberoastableUsers),
		len(results.Computers),
		len(results.UnconstrainedDelegation),
		getKeys(results.KerberoastableUsers),
		results.UnconstrainedDelegation,
	)
	
	return prompt
}

func getKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
