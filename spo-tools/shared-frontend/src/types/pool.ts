export interface RelaySpec {
  kind: 'single_host_addr' | 'single_host_name' | 'multi_host_name'
  port?: number | null
  ipv4?: string | null
  ipv6?: string | null
  dns?: string | null
}
