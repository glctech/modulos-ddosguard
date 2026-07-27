<?php declare(strict_types = 0);
namespace Modules\DDoSSOCOverview\Actions;
use CControllerDashboardWidgetView, CControllerResponseData;

class WidgetView extends CControllerDashboardWidgetView {
	protected function doAction(): void {
		$since = zbx_dbstr(date('Y-m-d H:i:s', time() - 86400));

		$r1 = DBfetch(DBselect(
			'SELECT COUNT(*) c, COALESCE(SUM(attempts),0) att, COUNT(DISTINCT src_ip) ips'
			.' FROM ddosguard_attacks WHERE created_at >= '.$since
		));
		$r2 = DBfetch(DBselect(
			'SELECT COUNT(*) c FROM ddosguard_blocks WHERE created_at >= '.$since
		));
		$r3 = DBfetch(DBselect(
			'SELECT COUNT(*) c FROM ddosguard_correlations WHERE resolved=0 AND severity_score>=7'
		));

		$events   = (int)($r1['c']   ?? 0);
		$attempts = (int)($r1['att'] ?? 0);
		$ips      = (int)($r1['ips'] ?? 0);
		$blocks   = (int)($r2['c']   ?? 0);
		$critical = (int)($r3['c']   ?? 0);
		$rate     = $events > 0 ? round($blocks / max($events,1) * 100, 1) : 0;

		$alerts = [];
		$res = DBselect(
			'SELECT a.attack_type, a.src_ip, a.severity_label, a.attempts, a.last_seen, h.name host'
			.' FROM ddosguard_attacks a LEFT JOIN hosts h ON h.hostid=a.hostid'
			.' ORDER BY a.last_seen DESC', 5
		);
		while ($row = DBfetch($res)) $alerts[] = $row;

		$hosts = [];
		$res2 = DBselect(
			'SELECT DISTINCT h.hostid, h.name host, h.status'
			.' FROM hosts h JOIN items i ON i.hostid=h.hostid'
			." WHERE i.key_ LIKE 'ddosguard%' AND h.status=0 AND h.flags=0"
			.' ORDER BY h.name', 8
		);
		while ($row = DBfetch($res2)) {
			$hb = DBfetch(DBselect(
				'SELECT hi.value FROM history_uint hi JOIN items it ON it.itemid=hi.itemid'
				.' WHERE it.hostid='.(int)$row['hostid']
				." AND it.key_='ddosguard.agent.heartbeat'"
				.' ORDER BY hi.clock DESC', 1
			));
			$row['heartbeat'] = $hb ? (int)$hb['value'] : 0;
			$hosts[] = $row;
		}

		$this->setResponse(new CControllerResponseData([
			'name'     => $this->getInput('name', $this->widget->getDefaultName()),
			'kpis'     => compact('events','attempts','ips','blocks','critical','rate'),
			'alerts'   => $alerts,
			'hosts'    => $hosts,
			'error'    => null,
			'user'     => ['debug_mode' => $this->getDebugMode()],
		]));
	}
}
