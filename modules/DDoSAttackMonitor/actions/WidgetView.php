<?php declare(strict_types = 0);
/**
 * DDoS Guard - Attack Monitor
 * Controller que monta os dados do painel de ataques: IP de origem,
 * país, tipo de ataque, porta/protocolo, tentativas, e se o host de
 * destino possui firewall/antivírus ativo.
 *
 * Lê das tabelas auxiliares criadas pelo módulo (ddosguard_attacks,
 * ddosguard_host_status) via DBselect() nativo do Zabbix - não exige
 * nenhuma classe interna além do que já está disponível para qualquer
 * módulo de frontend.
 */

namespace Modules\DDoSAttackMonitor\Actions;

use CControllerDashboardWidgetView,
	CControllerResponseData,
	API;

class WidgetView extends CControllerDashboardWidgetView {

	protected function doAction(): void {
		$hostids = $this->getResolvedHostIds();

		$minutes = (int) $this->fields_values['time_range'];
		$show_lines = (int) $this->fields_values['show_lines'];
		$order_by = (int) $this->fields_values['order_by'];
		$only_blocked = (int) $this->fields_values['only_blocked'] === 1;

		$attacks = $this->fetchAttacks($hostids, $minutes, $show_lines, $order_by, $only_blocked);
		$host_status = $this->fetchHostStatus($hostids);
		$summary = $this->fetchSummary($hostids, $minutes);

		$this->setResponse(new CControllerResponseData([
			'name' => $this->getInput('name', $this->widget->getDefaultName()),
			'attacks' => $attacks,
			'host_status' => $host_status,
			'summary' => $summary,
			'time_range' => $minutes,
			'error' => null,
			'user' => [
				'debug_mode' => $this->getDebugMode()
			]
		]));
	}

	/**
	 * Resolve os hostids selecionados no widget (filtro de host groups + hosts)
	 * usando a API padrão do Zabbix.
	 */
	private function getResolvedHostIds(): array {
		$groupids = $this->fields_values['groupids'] ?? [];
		$hostids = $this->fields_values['hostids'] ?? [];

		if (!$groupids && !$hostids) {
			return [];
		}

		$hosts = API::Host()->get([
			'output' => ['hostid'],
			'groupids' => $groupids ?: null,
			'hostids' => $hostids ?: null
		]);

		return array_column($hosts, 'hostid');
	}

	private function fetchAttacks(array $hostids, int $minutes, int $limit, int $order_by, bool $only_blocked): array {
		$sql = 'SELECT a.attack_id, a.hostid, a.src_ip, a.country_code, a.country_name, a.city,'.
			' a.attack_type, a.target_port, a.protocol, a.attempts, a.severity, a.blocked,'.
			' a.blocked_by, a.source_tool, a.first_seen, a.last_seen'.
			' FROM ddosguard_attacks a'.
			' WHERE a.last_seen >= '.zbx_dbstr(date('Y-m-d H:i:s', time() - $minutes * 60));

		if ($hostids) {
			$sql .= ' AND a.hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}
		if ($only_blocked) {
			$sql .= ' AND a.blocked = 1';
		}

		// order_by: 0 = tentativas (default), 1 = mais recente, 2 = severidade.
		switch ($order_by) {
			case 1:
				$sql .= ' ORDER BY a.last_seen DESC';
				break;
			case 2:
				$sql .= ' ORDER BY a.severity DESC, a.attempts DESC';
				break;
			default:
				$sql .= ' ORDER BY a.attempts DESC';
		}

		$result = DBselect($sql, $limit);

		$rows = [];
		$hostids_used = [];
		while ($row = DBfetch($result)) {
			$row['attempts'] = (int) $row['attempts'];
			$row['severity'] = (int) $row['severity'];
			$row['blocked'] = (int) $row['blocked'] === 1;
			$hostids_used[$row['hostid']] = true;
			$rows[] = $row;
		}

		// Anexa o nome do host (mais legível que o hostid puro).
		if ($hostids_used) {
			$hosts = API::Host()->get([
				'output' => ['hostid', 'name'],
				'hostids' => array_keys($hostids_used)
			]);
			$host_names = array_column($hosts, 'name', 'hostid');

			foreach ($rows as &$row) {
				$row['host_name'] = $host_names[$row['hostid']] ?? _('Desconhecido');
			}
			unset($row);
		}

		return $rows;
	}

	/**
	 * Indica, por host, se há firewall/antivírus ativo (reportado pelo
	 * agente coletor via evento "status").
	 */
	private function fetchHostStatus(array $hostids): array {
		$sql = 'SELECT hostid, has_firewall, firewall_name, has_antivirus, antivirus_name, last_heartbeat'.
			' FROM ddosguard_host_status';

		if ($hostids) {
			$sql .= ' WHERE hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}

		$result = DBselect($sql);
		$status = [];
		while ($row = DBfetch($result)) {
			$status[$row['hostid']] = [
				'has_firewall' => (int) $row['has_firewall'] === 1,
				'firewall_name' => $row['firewall_name'],
				'has_antivirus' => (int) $row['has_antivirus'] === 1,
				'antivirus_name' => $row['antivirus_name'],
				'last_heartbeat' => $row['last_heartbeat']
			];
		}

		return $status;
	}

	private function fetchSummary(array $hostids, int $minutes): array {
		$since = zbx_dbstr(date('Y-m-d H:i:s', time() - $minutes * 60));

		$sql = 'SELECT COUNT(*) AS total_events, COALESCE(SUM(attempts),0) AS total_attempts,'.
			' COUNT(DISTINCT src_ip) AS distinct_ips,'.
			' SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS total_blocked'.
			' FROM ddosguard_attacks WHERE last_seen >= '.$since;

		if ($hostids) {
			$sql .= ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}

		$row = DBfetch(DBselect($sql));

		return [
			'total_events' => (int) ($row['total_events'] ?? 0),
			'total_attempts' => (int) ($row['total_attempts'] ?? 0),
			'distinct_ips' => (int) ($row['distinct_ips'] ?? 0),
			'total_blocked' => (int) ($row['total_blocked'] ?? 0)
		];
	}
}
