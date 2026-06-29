<?php declare(strict_types = 0);
/**
 * DDoS Guard - Block Monitor
 * Painel: bloqueios realizados pelo firewall e pelo antivírus, em tempo real.
 */

namespace Modules\DDoSBlockMonitor;

use Zabbix\Core\CWidget;

class Widget extends CWidget {

	public function getDefaultName(): string {
		return _('DDoS Guard - Block Monitor (Firewall & Antivírus)');
	}

	public function getTranslationStrings(): array {
		return [];
	}
}
