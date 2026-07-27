<?php declare(strict_types = 0);
namespace Modules\DDoSMitreHeatmap;
use Zabbix\Core\CWidget;
class Widget extends CWidget {
	public function getDefaultName(): string {
		return _('DDoS Guard - MITRE ATT&CK Heatmap');
	}
	public function getTranslationStrings(): array {
		return [];
	}
}
