## k3d cluster configuration template for open-range.
## Variables are expanded by envsubst at cluster creation time.
## See k3d.env.example for variable documentation.
apiVersion: k3d.io/v1alpha5
kind: Simple
metadata:
  name: ${CLUSTER_NAME}
servers: 1
agents: ${K3D_AGENTS}
image: ${K3D_K3S_IMAGE}
subnet: ${K3D_SUBNET}
token: ${K3S_TOKEN}
kubeAPI:
  host: ${K3D_API_HOST}
  hostIP: ${K3D_API_HOST}
  hostPort: "${K3D_API_PORT}"
ports:
  # HTTP/HTTPS ingress via the k3d load-balancer
  - port: ${K3D_HTTP_PORT}:80
    nodeFilters:
      - loadbalancer
  - port: ${K3D_HTTPS_PORT}:443
    nodeFilters:
      - loadbalancer
  # DMZ NodePort range (30080-30089) mapped through to host
  - port: ${K3D_DMZ_PORT_START}-${K3D_DMZ_PORT_END}:${K3D_DMZ_PORT_START}-${K3D_DMZ_PORT_END}
    nodeFilters:
      - server:0
options:
  k3d:
    wait: true
    timeout: ${K3D_WAIT_TIMEOUT}
  k3s:
    extraArgs:
      # Disable Traefik -- open-range manages its own ingress
      - arg: --disable=traefik
        nodeFilters:
          - server:*
      # Disable default CNI for future Cilium support
      - arg: --flannel-backend=none
        nodeFilters:
          - server:*
      # Disable default network policy controller
      - arg: --disable-network-policy
        nodeFilters:
          - server:*
    nodeLabels:
      - label: openrange.io/role=agent
        nodeFilters:
          - agent:*
      - label: openrange.io/role=server
        nodeFilters:
          - server:*
