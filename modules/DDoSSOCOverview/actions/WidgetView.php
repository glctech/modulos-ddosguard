<?php declare(strict_types = 0);
/**
 * DDoS Guard - SOC Overview
 * Controller que monta o resumo executivo do SOC: KPIs, alertas recentes
 * e status de saúde dos hosts monitorados.
 *
 * Todos os números exibidos vêm de consultas reais ao banco - nenhum
 * valor é decorativo ou fixo. O KPI "Críticos" e o painel de hosts
 * refletem o estado atual (não uma janela de tempo); os demais KPIs e
 * "Alertas recentes" usam a mesma janela de tempo configurada no widget,
 * para que os números batam entre si.
 */

namespace Modules\DDoSSOCOverview\Actions;

use CControllerDashboardWidgetView,
	CControllerResponseData,
	API;

class WidgetView extends CControllerDashboardWidgetView {

	// Tempo sem heartbeat (segundos) para considerar um host sem
	// monitoramento ativo - mesmo padrão do macro {$DG.HEARTBEAT.TIMEOUT}
	// dos templates (15min).
	private const HEARTBEAT_STALE_SECONDS = 900;

	// Mesmo valor do ->setDefault() no WidgetForm - usado aqui como
	// fallback porque $fields_values só contém o que já foi salvo
	// explicitamente. Widgets criados antes deste campo existir (ex.:
	// via provision_dashboard.py, que registra "fields": []) não têm
	// "time_range" na configuração salva, e o default do formulário só
	// é aplicado na tela de edição — não em $fields_values na renderização.
	// Sem este fallback, a chave ausente gera "Undefined array key" e
	// (int) null vira 0, fazendo toda consulta usar uma janela de 0
	// minutos (tudo aparece zerado, mesmo com eventos reais).
	private const DEFAULT_TIME_RANGE_MINUTES = 1440;

	protected function doAction(): void {
		$hostids = $this->getResolvedHostIds();
		$minutes = (int) ($this->fields_values['time_range'] ?? self::DEFAULT_TIME_RANGE_MINUTES);
		$since = zbx_dbstr(date('Y-m-d H:i:s', time() - $minutes * 60));

		$host_filter = $hostids ? ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')' : '';

		$r1 = DBfetch(DBselect(
			'SELECT COUNT(*) c, COALESCE(SUM(attempts),0) att, COUNT(DISTINCT src_ip) ips'
			.' FROM ddosguard_attacks WHERE created_at >= '.$since.$host_filter
		));
		$r2 = DBfetch(DBselect(
			'SELECT COUNT(*) c FROM ddosguard_blocks WHERE created_at >= '.$since.$host_filter
		));
		$r3 = DBfetch(DBselect(
			'SELECT COUNT(*) c FROM ddosguard_correlations WHERE resolved=0 AND severity_score>=7'
			.($hostids ? ' AND hostid IN ('.implode(',', array_map('intval', $hostids)).')' : '')
		));

		$events   = (int) ($r1['c']   ?? 0);
		$attempts = (int) ($r1['att'] ?? 0);
		$ips      = (int) ($r1['ips'] ?? 0);
		$blocks   = (int) ($r2['c']   ?? 0);
		$critical = (int) ($r3['c']   ?? 0);

		$alerts = [];
		$sql = 'SELECT a.attack_type, a.src_ip, a.severity_label, a.attempts, a.last_seen, h.name host'
			.' FROM ddosguard_attacks a LEFT JOIN hosts h ON h.hostid=a.hostid'
			.' WHERE a.created_at >= '.$since.($host_filter !== '' ? ' AND a.hostid IN ('.implode(',', array_map('intval', $hostids)).')' : '')
			.' ORDER BY a.last_seen DESC';
		$res = DBselect($sql, 5);
		while ($row = DBfetch($res)) $alerts[] = $row;

		$hosts = $this->fetchHostsStatus($hostids);
		$stale_hosts = array_filter($hosts, static fn(array $h): bool => !$h['online']);

		$this->setResponse(new CControllerResponseData([
			'name'        => $this->getInput('name', $this->widget->getDefaultName()),
			'time_range'  => $minutes,
			'kpis'        => compact('events', 'attempts', 'ips', 'blocks', 'critical'),
			'alerts'      => $alerts,
			'hosts'       => $hosts,
			'stale_count' => count($stale_hosts),
			'error'       => null,
			'user'        => [
				'debug_mode' => $this->getDebugMode()
			]
		]));
	}

	/**
	 * Resolve os hostids selecionados no widget (filtro de host groups + hosts).
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

	/**
	 * Status de cada host que envia dados ao DDoS Guard: online só se o
	 * ÚLTIMO heartbeat recebido está dentro da janela de "fresco"
	 * (HEARTBEAT_STALE_SECONDS) - não basta ter recebido algum heartbeat
	 * em algum momento do passado. Sem essa checagem de horário, um host
	 * cujo agente morreu há dias continua aparecendo como "OK" para
	 * sempre, porque o único valor que o item de heartbeat recebe é
	 * sempre 1 (ver ddos_guard_agent.py / ingest.php).
	 */
	private function fetchHostsStatus(array $hostids): array {
		$sql = 'SELECT DISTINCT h.hostid, h.name host'
			.' FROM hosts h JOIN items i ON i.hostid=h.hostid'
			." WHERE i.key_ LIKE 'ddosguard%' AND h.status=0 AND h.flags=0";
		if ($hostids) {
			$sql .= ' AND h.hostid IN ('.implode(',', array_map('intval', $hostids)).')';
		}
		$sql .= ' ORDER BY h.name';

		$hosts = [];
		$res = DBselect($sql, 10);
		while ($row = DBfetch($res)) {
			$hb = DBfetch(DBselect(
				'SELECT hi.value, hi.clock FROM history_uint hi JOIN items it ON it.itemid=hi.itemid'
				.' WHERE it.hostid='.(int) $row['hostid']
				." AND it.key_='ddosguard.agent.heartbeat'"
				.' ORDER BY hi.clock DESC', 1
			));
			$last_clock = $hb ? (int) $hb['clock'] : 0;
			$age = $last_clock > 0 ? (time() - $last_clock) : null;

			$hosts[] = [
				'hostid'        => $row['hostid'],
				'host'          => $row['host'],
				'online'        => $last_clock > 0 && $age <= self::HEARTBEAT_STALE_SECONDS,
				'last_heartbeat'=> $last_clock,
				'age_seconds'   => $age,
			];
		}
		return $hosts;
	}
}
