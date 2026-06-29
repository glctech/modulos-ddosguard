<?php declare(strict_types = 0);
/**
 * DDoS Guard - Attack Monitor
 * Painel: IP de origem, país, tipo de ataque, tentativas, firewall/antivírus.
 */

namespace Modules\DDoSAttackMonitor;

use Zabbix\Core\CWidget;

class Widget extends CWidget {

	public function getDefaultName(): string {
		return _('DDoS Guard - Attack Monitor');
	}

	public function getTranslationStrings(): array {
		return [];
	}
}
