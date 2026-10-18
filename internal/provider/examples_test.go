package provider

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// TestExample_saasWorkspace applies examples/saas-workspace against the fake API and checks its policy assertions.
func TestExample_saasWorkspace(t *testing.T) {
	raw, err := os.ReadFile("../../examples/saas-workspace/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	// Drop the terraform and provider blocks; the test supplies its own provider configuration.
	body := regexp.MustCompile(`(?ms)^terraform \{.*?^\}\n`).ReplaceAllString(string(raw), "")
	body = strings.Replace(body, `provider "permio" {}`, "", 1)

	e := newTestEnv(t)
	cfg := e.config(body)
	e.run(
		resource.TestStep{
			Config: cfg,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("permio_role.admin", tfjsonpath.New("permissions"), knownvalue.SetSizeExact(8)),
				statecheck.ExpectKnownValue("permio_grant.support", tfjsonpath.New("roles"), knownvalue.SetSizeExact(2)),
				statecheck.ExpectKnownValue("permio_group_members.engineering", tfjsonpath.New("members"),
					knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("user_bob"), knownvalue.StringExact("user_carol")})),
			},
		},
		// Once the grants exist, the policy checks see them, and nothing has drifted.
		resource.TestStep{
			Config:           cfg,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.permio_check.engineer_can_delete_platform_docs", tfjsonpath.New("allowed"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue("data.permio_check.support_cannot_manage_billing", tfjsonpath.New("allowed"), knownvalue.Bool(false)),
			},
		},
	)
}
