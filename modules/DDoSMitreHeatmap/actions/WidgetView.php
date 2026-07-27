<?php declare(strict_types = 0);
namespace Modules\DDoSMitreHeatmap\Actions;
use CControllerDashboardWidgetView, CControllerResponseData;

class WidgetView extends CControllerDashboardWidgetView {
	protected function doAction(): void {
		$since = zbx_dbstr(date('Y-m-d H:i:s', time() - 86400));
		$tactics = [
			'Credential Access'   => ['color'=>'#d63939','count'=>0,'tech'=>'--'],
			'Impact'              => ['color'=>'#d63939','count'=>0,'tech'=>'--'],
			'Reconnaissance'      => ['color'=>'#f0a30a','count'=>0,'tech'=>'--'],
			'Initial Access'      => ['color'=>'#f0a30a','count'=>0,'tech'=>'--'],
			'Command and Control' => ['color'=>'#9b59b6','count'=>0,'tech'=>'--'],
			'Execution'           => ['color'=>'#4b8cb8','count'=>0,'tech'=>'--'],
		];
		$seen = [];
		$res = DBselect(
			'SELECT mitre_tactic, mitre_technique, COUNT(*) c'
			.' FROM ddosguard_attacks'
			." WHERE mitre_tactic IS NOT NULL AND mitre_tactic != ''"
			.' AND created_at >= '.$since
			.' GROUP BY mitre_tactic, mitre_technique ORDER BY c DESC'
		);
		while ($row = DBfetch($res)) {
			$t = $row['mitre_tactic'];
			if (!isset($tactics[$t])) continue;
			$tactics[$t]['count'] += (int)$row['c'];
			if (!isset($seen[$t])) { $tactics[$t]['tech'] = $row['mitre_technique']??'--'; $seen[$t]=true; }
		}
		$out = [];
		foreach ($tactics as $name => $d) {
			$out[] = ['tactic'=>$name,'color'=>$d['color'],'count'=>$d['count'],'tech'=>$d['tech']];
		}
		$this->setResponse(new CControllerResponseData([
			'name'    => $this->getInput('name', $this->widget->getDefaultName()),
			'tactics' => $out,
			'error'   => null,
			'user'    => ['debug_mode' => $this->getDebugMode()],
		]));
	}
}
