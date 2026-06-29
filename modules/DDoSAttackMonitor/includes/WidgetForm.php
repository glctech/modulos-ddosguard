<?php declare(strict_types = 0);
/**
 * DDoS Guard - Attack Monitor - formulário de configuração do widget.
 */

namespace Modules\DDoSAttackMonitor\Includes;

use Zabbix\Widgets\CWidgetForm;

use Zabbix\Widgets\Fields\{
	CWidgetFieldCheckBox,
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
				(new CWidgetFieldSelect('order_by', _('Ordenar por'), [
					0 => _('Quantidade de tentativas'),
					1 => _('Mais recente'),
					2 => _('Severidade')
				]))->setDefault(0)
			)
			->addField(
				(new CWidgetFieldCheckBox('only_blocked', _('Mostrar apenas ataques bloqueados')))
					->setDefault(0)
			);
	}
}
