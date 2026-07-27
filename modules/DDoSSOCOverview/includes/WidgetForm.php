<?php declare(strict_types = 0);
namespace Modules\DDoSSOCOverview\Includes;
use Zabbix\Widgets\CWidgetForm;
use Zabbix\Widgets\Fields\CWidgetFieldMultiSelectGroup;
use Zabbix\Widgets\Fields\CWidgetFieldMultiSelectHost;
class WidgetForm extends CWidgetForm {
	public function addFields(): self {
		return $this
			->addField(new CWidgetFieldMultiSelectGroup('groupids', _('Host groups')))
			->addField(new CWidgetFieldMultiSelectHost('hostids', _('Hosts')));
	}
}
