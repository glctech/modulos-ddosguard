<?php declare(strict_types = 0);
/**
 * DDoS Guard - Block Monitor
 * Controller que monta os dados do painel de bloqueios (firewall +
 * antivírus): IP de origem, país, regra/assinatura, host, horário, e
 * contadores comparativos firewall vs antivírus.
 */

namespace Modules\DDoSBlockMonitor\Actions;

use CControllerDashboardWidgetView,
	CControllerResponseData,
	API;

class WidgetView extends CControllerDashboardWidgetView {

	protected function doAction(): void {
		$hostids = $this->getResolvedHostIds();

		$minutes = (int) $this->fields_values['time_range'];
		$show_lines = (int) $this->fields_values['show_lines'];
		$source_filter = (int) $this->fields_values['block_source_filter'];

		$blocks = $this->fetchBlocks($hostids, $minutes, $show_lines, $source_filter);
		$counters = $this->fetchCounters($hostids, $minutes);

		$this->setResponse(new CControllerResponseData([
			'name' => $this->getInput('name', $this->widget->getDefaultName()),
			'blocks' => $blocks,
			'counters' => $counters,
			'time_range' => $minutes,
			'error' => null,
			'user' => [
				'debug_mode' => $this->getDebugMode()
			]
		]));
	}

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

	private function fetchBlocks(array $hostids, int $minutes, int $limit, int $source_filter): array {
		$sql = 'SELECT block_id, hostid, src_ip, country_code, country_name, block_source, tool,'.
			' rule_or_signature, target_port, protocol, reason, file_path, event_time'.
			' FROM ddosguard_blocks'.
			' WHERE event_time >= '.zbx_dbstr(date('Y-m-d H:i:s', time() - $minutes * 60));

		if ($hostids) {
			$sql .= ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}

		// source_filter: 0 = todos (default), 1 = apenas firewall, 2 = apenas antivírus.
		if ($source_filter === 1) {
			$sql .= ' AND block_source = '.zbx_dbstr('firewall');
		}
		elseif ($source_filter === 2) {
			$sql .= ' AND block_source = '.zbx_dbstr('antivirus');
		}

		$sql .= ' ORDER BY event_time DESC';

		$result = DBselect($sql, $limit);

		$rows = [];
		$hostids_used = [];
		while ($row = DBfetch($result)) {
			$hostids_used[$row['hostid']] = true;
			$rows[] = $row;
		}

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
	 * Contadores comparativos para o painel "Bloqueados: Firewall x Antivírus".
	 */
	private function fetchCounters(array $hostids, int $minutes): array {
		$since = zbx_dbstr(date('Y-m-d H:i:s', time() - $minutes * 60));

		$sql = 'SELECT block_source, COUNT(*) AS total, COUNT(DISTINCT src_ip) AS distinct_ips'.
			' FROM ddosguard_blocks WHERE event_time >= '.$since;

		if ($hostids) {
			$sql .= ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}

		$sql .= ' GROUP BY block_source';

		$result = DBselect($sql);

		$counters = [
			'firewall' => ['total' => 0, 'distinct_ips' => 0],
			'antivirus' => ['total' => 0, 'distinct_ips' => 0]
		];

		while ($row = DBfetch($result)) {
			if (isset($counters[$row['block_source']])) {
				$counters[$row['block_source']] = [
					'total' => (int) $row['total'],
					'distinct_ips' => (int) $row['distinct_ips']
				];
			}
		}

		// Top países bloqueados (para o gráfico/lista de origem).
		$sql_countries = 'SELECT country_name, country_code, COUNT(*) AS total'.
			' FROM ddosguard_blocks WHERE event_time >= '.$since.
			' AND country_code IS NOT NULL';

		if ($hostids) {
			$sql_countries .= ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}

		$sql_countries .= ' GROUP BY country_name, country_code ORDER BY total DESC';

		$top_countries = [];
		$result_c = DBselect($sql_countries, 5);
		while ($row = DBfetch($result_c)) {
			$top_countries[] = $row;
		}
		$counters['top_countries'] = $top_countries;

		return $counters;
	}
}
