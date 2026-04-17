from open_range.render.cilium import CiliumPolicyGenerator


def test_default_deny_policy_includes_explicit_ingress_list() -> None:
    generator = CiliumPolicyGenerator(name_prefix="or-demo")

    policy = generator._default_deny("dmz", "or-demo-dmz")

    assert policy["spec"]["endpointSelector"] == {}
    assert policy["spec"]["ingress"] == []


def test_dns_egress_selects_kubernetes_dns_labels_with_cilium_prefix() -> None:
    generator = CiliumPolicyGenerator(name_prefix="or-demo")

    policy = generator._dns_egress("dmz", "or-demo-dmz")

    selector = policy["spec"]["egress"][0]["toEndpoints"][0]["matchLabels"]
    port_rule = policy["spec"]["egress"][0]["toPorts"][0]

    assert selector["k8s:io.kubernetes.pod.namespace"] == "kube-system"
    assert selector["k8s:k8s-app"] == "kube-dns"
    assert "k8s-app" not in selector
    assert "rules" not in port_rule


def test_same_zone_policy_allows_egress_within_namespace() -> None:
    generator = CiliumPolicyGenerator(name_prefix="or-demo")

    policy = generator._allow_same_zone("dmz", "or-demo-dmz")

    egress_selector = policy["spec"]["egress"][0]["toEndpoints"][0]["matchLabels"]

    assert egress_selector["k8s:io.kubernetes.pod.namespace"] == "or-demo-dmz"


def test_cross_zone_generation_emits_matching_source_egress_policy() -> None:
    generator = CiliumPolicyGenerator(name_prefix="or-demo")

    policies = generator.generate_zone_policies(
        zones={"external": [], "dmz": []},
        firewall_rules=[
            {
                "action": "allow",
                "fromZone": "external",
                "toZone": "dmz",
                "ports": [80],
            }
        ],
    )

    egress_policy = next(
        policy
        for policy in policies
        if policy["metadata"]["name"] == "allow-egress-to-dmz"
    )

    assert egress_policy["metadata"]["namespace"] == "or-demo-external"
    assert egress_policy["metadata"]["labels"]["openrange/policy-type"] == (
        "cross-zone-egress"
    )
    assert egress_policy["spec"]["egress"][0]["toEndpoints"][0]["matchLabels"] == {
        "k8s:io.kubernetes.pod.namespace": "or-demo-dmz"
    }
    assert egress_policy["spec"]["egress"][0]["toPorts"][0]["ports"] == [
        {"port": "80", "protocol": "TCP"}
    ]
