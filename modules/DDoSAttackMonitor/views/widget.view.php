<?php declare(strict_types = 0);
/**
 * DDoS Guard - Attack Monitor - view.
 *
 * @var CView $this
 * @var array $data
 */

$severity_labels = [
	0 => _('Info'),
	1 => _('Baixa'),
	2 => _('Média'),
	3 => _('Alta'),
	4 => _('Crítica')
];

$style = (new CTag('style', true))->addItem('
	.ddosguard-summary { display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
	.ddosguard-summary-card {
		flex: 1; min-width: 120px; background: rgba(128,128,128,.08);
		border-radius: 4px; padding: 8px 12px; text-align: center;
	}
	.ddosguard-summary-value { font-size: 22px; font-weight: bold; }
	.ddosguard-danger { color: #d63939; }
	.ddosguard-ok { color: #2fa84f; }
	.ddosguard-attempts { font-weight: bold; }
');

$severity_classes = [
	0 => ZBX_STYLE_GREY,
	1 => ZBX_STYLE_GREEN,
	2 => ZBX_STYLE_YELLOW_BG,
	3 => ZBX_STYLE_ORANGE,
	4 => ZBX_STYLE_RED_BG
];

// ---------------------------------------------------------------------
// Cartões de resumo (topo do painel)
// ---------------------------------------------------------------------
$summary = $data['summary'];

$summary_div = (new CDiv())
	->addClass('ddosguard-summary')
	->addItem(
		(new CDiv())
			->addClass('ddosguard-summary-card')
			->addItem(new CDiv(_('Eventos de ataque')))
			->addItem((new CDiv($summary['total_events']))->addClass('ddosguard-summary-value'))
	)
	->addItem(
		(new CDiv())
			->addClass('ddosguard-summary-card')
			->addItem(new CDiv(_('Tentativas totais')))
			->addItem((new CDiv($summary['total_attempts']))->addClass('ddosguard-summary-value ddosguard-danger'))
	)
	->addItem(
		(new CDiv())
			->addClass('ddosguard-summary-card')
			->addItem(new CDiv(_('IPs de origem distintos')))
			->addItem((new CDiv($summary['distinct_ips']))->addClass('ddosguard-summary-value'))
	)
	->addItem(
		(new CDiv())
			->addClass('ddosguard-summary-card')
			->addItem(new CDiv(_('Bloqueados')))
			->addItem((new CDiv($summary['total_blocked']))->addClass('ddosguard-summary-value ddosguard-ok'))
	);

// ---------------------------------------------------------------------
// Tabela principal de ataques
// ---------------------------------------------------------------------
if ($data['error'] !== null) {
	$table = (new CTableInfo())->setNoDataMessage($data['error']);
}
else {
	$table = (new CTableInfo())
		->setHeader([
			_('Host'),
			_('IP de origem'),
			_('País'),
			_('Tipo de ataque'),
			_('Porta/Proto'),
			_('Tentativas'),
			_('Severidade'),
			_('Bloqueado'),
			_('Firewall'),
			_('Antivírus'),
			_('Última atividade')
		]);

	if (!$data['attacks']) {
		$table->setNoDataMessage(_('Nenhum ataque detectado no período selecionado.'));
	}

	foreach ($data['attacks'] as $attack) {
		$hostid = $attack['hostid'];
		$status = $data['host_status'][$hostid] ?? null;

		$country_label = $attack['country_name']
			?: ($attack['country_code'] ?: _('Desconhecido'));
		if ($attack['country_code']) {
			$country_label = $attack['country_code'].' - '.$country_label;
		}

		$blocked_cell = $attack['blocked']
			? (new CSpan(_('Sim')))->addClass(ZBX_STYLE_GREEN)
			: (new CSpan(_('Não')))->addClass(ZBX_STYLE_RED);

		$firewall_cell = ($status && $status['has_firewall'])
			? (new CSpan($status['firewall_name'] ?: _('Ativo')))->addClass(ZBX_STYLE_GREEN)
			: (new CSpan(_('Não detectado')))->addClass(ZBX_STYLE_GREY);

		$antivirus_cell = ($status && $status['has_antivirus'])
			? (new CSpan($status['antivirus_name'] ?: _('Ativo')))->addClass(ZBX_STYLE_GREEN)
			: (new CSpan(_('Não detectado')))->addClass(ZBX_STYLE_GREY);

		$severity_cell = (new CSpan($severity_labels[$attack['severity']] ?? $attack['severity']))
			->addClass($severity_classes[$attack['severity']] ?? '');

		$table->addRow([
			$attack['host_name'] ?? _('—'),
			$attack['src_ip'],
			$country_label,
			$attack['attack_type'],
			$attack['protocol']
				? $attack['protocol'].'/'.($attack['target_port'] ?? '-')
				: ($attack['target_port'] ?? '-'),
			(new CSpan($attack['attempts']))->addClass('ddosguard-attempts'),
			$severity_cell,
			$blocked_cell,
			$firewall_cell,
			$antivirus_cell,
			date('Y-m-d H:i:s', strtotime($attack['last_seen']))
		]);
	}
}

(new CWidgetView($data))
	->addItem($style)
	->addItem($summary_div)
	->addItem($table)
	->show();
