<?php declare(strict_types = 0);
namespace Modules\DDoSSOCOverview;
use Zabbix\Core\CWidget;
class Widget extends CWidget {
	public function getDefaultName(): string {
		return _('DDoS Guard - SOC Overview');
	}
	public function getTranslationStrings(): array {
		return [];
	}
}
