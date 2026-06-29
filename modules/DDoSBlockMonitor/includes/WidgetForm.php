<?php declare(strict_types = 0);
/**
 * DDoS Guard - Block Monitor - formulário de configuração do widget.
 */

namespace Modules\DDoSBlockMonitor\Includes;

use Zabbix\Widgets\CWidgetForm;

use Zabbix\Widgets\Fields\{
	CWidgetFieldIntegerBox,
	CWidgetFieldMultiSelectGroup,
	CWidgetFieldMultiSelectHost,
	CWidgetFieldSelect
};

class WidgetForm extends CWidgetForm {

	public function addFields(): self {
		return $this
			->addField(
				new CWidgetFieldMultiSelectGroup('groupids', _('Host groups'))
			)
			->addField(
				new CWidgetFieldMultiSelectHost('hostids', _('Hosts'))
			)
			->addField(
				(new CWidgetFieldSelect('time_range', _('Janela de tempo'), [
					5 => _('Últimos 5 minutos'),
					15 => _('Últimos 15 minutos'),
					60 => _('Última hora'),
					360 => _('Últimas 6 horas'),
					1440 => _('Últimas 24 horas')
				]))->setDefault(60)
			)
			->addField(
				(new CWidgetFieldIntegerBox('show_lines', _('Número de linhas'), 1, 100))
					->setDefault(25)
			)
			->addField(
				(new CWidgetFieldSelect('block_source_filter', _('Mostrar bloqueios de'), [
					0 => _('Firewall + Antivírus'),
					1 => _('Apenas Firewall'),
					2 => _('Apenas Antivírus')
				]))->setDefault(0)
			);
	}
}
