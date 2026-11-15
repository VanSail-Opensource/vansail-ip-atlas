package admission

// permittedDistributionDecision is a project admission decision, not a grant
// from the publisher. Educational use must remain explicit in the reviewed
// source catalog; it cannot be inferred from unknown or denied rights. The
// complete decision, evidence, review basis and credits remain bound by the
// configuration policy and RightsDigests. Other admission controls are separate.
func permittedDistributionDecision(decision string) bool {
	switch decision {
	case "allow", "user_authorized_educational_use":
		return true
	default:
		return false
	}
}
