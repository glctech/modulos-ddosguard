<?php declare(strict_types = 0);
namespace Modules\DDoSSOCOverview\Includes;
use Zabbix\Widgets\CWidgetForm;
use Zabbix\Widgets\Fields\CWidgetFieldMultiSelectGroup;
use Zabbix\Widgets\Fields\CWidgetFieldMultiSelectHost;
use Zabbix\Widgets\Fields\CWidgetFieldSelect;
class WidgetForm extends CWidgetForm {
	public function addFields(): self {
		return $this
			->addField(new CWidgetFieldMultiSelectGroup('groupids', _('Host groups')))
			->addField(new CWidgetFieldMultiSelectHost('hostids', _('Hosts')))
			->addField(
				(new CWidgetFieldSelect('time_range', _('Janela de tempo'), [
					60 => _('Última hora'),
					360 => _('Últimas 6 horas'),
					1440 => _('Últimas 24 horas'),
					10080 => _('Últimos 7 dias')
				]))->setDefault(1440)
			);
	}
}
