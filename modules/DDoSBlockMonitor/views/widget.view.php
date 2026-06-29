<?php declare(strict_types = 0);
/**
 * DDoS Guard - Block Monitor - view.
 *
 * @var CView $this
 * @var array $data
 */

$counters = $data['counters'];
$fw = $counters['firewall'];
$av = $counters['antivirus'];
$max_total = max($fw['total'], $av['total'], 1);

$style = (new CTag('style', true))->addItem('
	.ddosguard-compare { display: flex; gap: 16px; margin-bottom: 14px; flex-wrap: wrap; }
	.ddosguard-compare-card {
		flex: 1; min-width: 200px; background: rgba(128,128,128,.08);
		border-radius: 4px; padding: 10px 14px;
	}
	.ddosguard-compare-title { font-weight: bold; margin-bottom: 6px; display: flex; justify-content: space-between; }
	.ddosguard-bar-bg { background: rgba(128,128,128,.2); border-radius: 3px; height: 10px; overflow: hidden; }
	.ddosguard-bar-fill { height: 10px; border-radius: 3px; }
	.ddosguard-bar-fw { background: #2f9e44; }
	.ddosguard-bar-av { background: #f08c00; }
	.ddosguard-compare-sub { font-size: 11px; color: #888; margin-top: 4px; }
	.ddosguard-countries { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
	.ddosguard-country-chip {
		background: rgba(128,128,128,.12); border-radius: 12px; padding: 3px 10px; font-size: 12px;
	}
');

// ---------------------------------------------------------------------
// Cartões comparativos Firewall x Antivírus
// ---------------------------------------------------------------------
$fw_pct = (int) round(($fw['total'] / $max_total) * 100);
$av_pct = (int) round(($av['total'] / $max_total) * 100);

$compare_div = (new CDiv())
	->addClass('ddosguard-compare')
	->addItem(
		(new CDiv())
			->addClass('ddosguard-compare-card')
			->addItem(
				(new CDiv())
					->addClass('ddosguard-compare-title')
					->addItem(new CSpan(_('🛡 Firewall')))
					->addItem(new CSpan($fw['total']))
			)
			->addItem(
				(new CDiv())
					->addClass('ddosguard-bar-bg')
					->addItem((new CDiv())->addClass('ddosguard-bar-fill ddosguard-bar-fw')
						->setAttribute('style', 'width:'.$fw_pct.'%'))
			)
			->addItem(
				(new CDiv(_s('%1$d IPs distintos bloqueados', $fw['distinct_ips'])))
					->addClass('ddosguard-compare-sub')
			)
	)
	->addItem(
		(new CDiv())
			->addClass('ddosguard-compare-card')
			->addItem(
				(new CDiv())
					->addClass('ddosguard-compare-title')
					->addItem(new CSpan(_('🦠 Antivírus')))
					->addItem(new CSpan($av['total']))
			)
			->addItem(
				(new CDiv())
					->addClass('ddosguard-bar-bg')
					->addItem((new CDiv())->addClass('ddosguard-bar-fill ddosguard-bar-av')
						->setAttribute('style', 'width:'.$av_pct.'%'))
			)
			->addItem(
				(new CDiv(_s('%1$d IPs distintos / ameaças', $av['distinct_ips'])))
					->addClass('ddosguard-compare-sub')
			)
	);

// ---------------------------------------------------------------------
// Top países de origem dos bloqueios
// ---------------------------------------------------------------------
$countries_div = null;
if ($counters['top_countries']) {
	$countries_div = new CDiv();
	$countries_div->addClass('ddosguard-countries');
	foreach ($counters['top_countries'] as $c) {
		$label = ($c['country_code'] ?: '').' '.($c['country_name'] ?: _('Desconhecido')).' ('.$c['total'].')';
		$countries_div->addItem((new CSpan($label))->addClass('ddosguard-country-chip'));
	}
}

// ---------------------------------------------------------------------
// Tabela de eventos de bloqueio
// ---------------------------------------------------------------------
if ($data['error'] !== null) {
	$table = (new CTableInfo())->setNoDataMessage($data['error']);
}
else {
	$table = (new CTableInfo())
		->setHeader([
			_('Origem'),
			_('Host protegido'),
			_('IP de origem'),
			_('País'),
			_('Ferramenta'),
			_('Regra / Assinatura'),
			_('Porta/Proto'),
			_('Motivo / Malware'),
			_('Horário')
		]);

	if (!$data['blocks']) {
		$table->setNoDataMessage(_('Nenhum bloqueio registrado no período selecionado.'));
	}

	foreach ($data['blocks'] as $block) {
		$is_firewall = $block['block_source'] === 'firewall';

		$origin_cell = $is_firewall
			? (new CSpan(_('🛡 Firewall')))->addClass(ZBX_STYLE_GREEN)
			: (new CSpan(_('🦠 Antivírus')))->addClass(ZBX_STYLE_ORANGE);

		$country_label = $block['country_name']
			?: ($block['country_code'] ?: _('—'));
		if ($block['country_code']) {
			$country_label = $block['country_code'].' - '.$country_label;
		}

		$rule_or_sig = $block['rule_or_signature'] ?: '—';
		$reason_or_malware = $is_firewall
			? ($block['reason'] ?: '—')
			: ($block['rule_or_signature'] ?: ($block['reason'] ?: '—'));

		$table->addRow([
			$origin_cell,
			$block['host_name'] ?? '—',
			$block['src_ip'],
			$country_label,
			$block['tool'] ?: '—',
			$is_firewall ? $rule_or_sig : ($block['file_path'] ?: '—'),
			$block['protocol'] ? $block['protocol'].'/'.($block['target_port'] ?? '-') : '-',
			$reason_or_malware,
			date('Y-m-d H:i:s', strtotime($block['event_time']))
		]);
	}
}

(new CWidgetView($data))
	->addItem($style)
	->addItem($compare_div)
	->addItem($countries_div)
	->addItem($table)
	->show();
