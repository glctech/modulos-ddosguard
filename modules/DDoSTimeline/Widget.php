<?php declare(strict_types = 0);
namespace Modules\DDoSTimeline;
use Zabbix\Core\CWidget;
class Widget extends CWidget {
	public function getDefaultName(): string {
		return _('DDoS Guard - Response Timeline');
	}
	public function getTranslationStrings(): array {
		return [];
	}
}
