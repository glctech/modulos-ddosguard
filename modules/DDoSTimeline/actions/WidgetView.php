<?php declare(strict_types = 0);
namespace Modules\DDoSTimeline\Actions;
use CControllerDashboardWidgetView, CControllerResponseData;

class WidgetView extends CControllerDashboardWidgetView {
	protected function doAction(): void {
		$since7d  = zbx_dbstr(date('Y-m-d H:i:s', time() - 604800));
		$since24h = zbx_dbstr(date('Y-m-d H:i:s', time() - 86400));

		$incidents = [];
		$res = DBselect(
			'SELECT a.attack_type, a.src_ip, a.country_name, a.severity_label,'
			.' a.severity_score, a.attempts, a.last_seen, a.mitre_technique,'
			.' h.name host,'
			.' TIMESTAMPDIFF(MINUTE, a.first_seen, a.last_seen) duration_min'
			.' FROM ddosguard_attacks a LEFT JOIN hosts h ON h.hostid=a.hostid'
			.' WHERE a.created_at >= '.$since7d.' AND a.severity_score >= 3'
			.' ORDER BY a.last_seen DESC', 12
		);
		while ($row = DBfetch($res)) $incidents[] = $row;

		$stats = DBfetch(DBselect(
			'SELECT COUNT(*) total, COUNT(DISTINCT src_ip) ips,'
			.' COALESCE(MAX(attempts),0) max_att'
			.' FROM ddosguard_attacks WHERE created_at >= '.$since24h
		));

		$this->setResponse(new CControllerResponseData([
			'name'      => $this->getInput('name', $this->widget->getDefaultName()),
			'incidents' => $incidents,
			'stats'     => $stats ?? [],
			'error'     => null,
			'user'      => ['debug_mode' => $this->getDebugMode()],
		]));
	}
}
