<?php declare(strict_types = 0);
/**
 * DDoS Guard - Block Monitor - view (v2.3)
 * @var CView $this
 * @var array $data
 */

$counters  = $data['counters'];
$fw        = $counters['firewall'];
$av        = $counters['antivirus'];
$max_total = max($fw['total'], $av['total'], 1);

$style = (new CTag('style', true))->addItem('
	.dgblk { display: flex; flex-direction: column; gap: 8px; }
	.dgblk-cards { display: flex; gap: 8px; }
	.dgblk-card {
		flex: 1; border-radius: 4px; padding: 10px 14px;
		background: rgba(128,128,128,.07);
		border: 1px solid rgba(128,128,128,.12);
		border-top: 2px solid #ccc;
	}
	.dgblk-card-fw { border-top-color: #2fa84f; }
	.dgblk-card-av { border-top-color: #f0a30a; }
	.dgblk-card-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
	.dgblk-card-title { font-size: 11px; font-weight: 700; }
	.dgblk-card-count { font-size: 22px; font-weight: 700; font-family: monospace; line-height: 1; }
	.dgblk-bar-bg { background: rgba(128,128,128,.2); border-radius: 3px; height: 5px; overflow: hidden; margin-bottom: 5px; }
	.dgblk-bar-fw { height: 5px; border-radius: 3px; background: #2fa84f; }
	.dgblk-bar-av { height: 5px; border-radius: 3px; background: #f0a30a; }
	.dgblk-card-sub { font-size: 10px; color: #999; }
	.dgblk-countries { display: flex; gap: 6px; flex-wrap: wrap; }
	.dgblk-country { background: rgba(128,128,128,.1); border-radius: 10px; padding: 3px 10px; font-size: 11px; }
	.dgblk-fw { color: #2fa84f; font-weight: 600; font-size: 11px; }
	.dgblk-av { color: #f0a30a; font-weight: 600; font-size: 11px; }
');

$fw_pct = (int) round(($fw['total'] / $max_total) * 100);
$av_pct = (int) round(($av['total'] / $max_total) * 100);

$cards = (new CDiv())->addClass('dgblk-cards');
$cards->addItem(
	(new CDiv())
		->addClass('dgblk-card dgblk-card-fw')
		->addItem(
			(new CDiv())
				->addClass('dgblk-card-head')
				->addItem((new CDiv(_('Firewall')))->addClass('dgblk-card-title'))
				->addItem((new CDiv($fw['total']))->addClass('dgblk-card-count')->addStyle('color:#2fa84f'))
		)
		->addItem((new CDiv())->addClass('dgblk-bar-bg')
			->addItem((new CDiv())->addClass('dgblk-bar-fw')->addStyle('width:'.$fw_pct.'%')))
		->addItem((new CDiv(_s('%1$d IPs distintos bloqueados', $fw['distinct_ips'])))->addClass('dgblk-card-sub'))
);
$cards->addItem(
	(new CDiv())
		->addClass('dgblk-card dgblk-card-av')
		->addItem(
			(new CDiv())
				->addClass('dgblk-card-head')
				->addItem((new CDiv(_('Antivirus')))->addClass('dgblk-card-title'))
				->addItem((new CDiv($av['total']))->addClass('dgblk-card-count')->addStyle('color:#f0a30a'))
		)
		->addItem((new CDiv())->addClass('dgblk-bar-bg')
			->addItem((new CDiv())->addClass('dgblk-bar-av')->addStyle('width:'.$av_pct.'%')))
		->addItem((new CDiv(_s('%1$d IPs distintos / ameacas', $av['distinct_ips'])))->addClass('dgblk-card-sub'))
);

$countries_div = null;
if ($counters['top_countries']) {
	$countries_div = (new CDiv())->addClass('dgblk-countries');
	foreach ($counters['top_countries'] as $c) {
		$label = ($c['country_code'] ?: '').($c['country_name'] ? ' '.$c['country_name'] : ' ?').' ('.$c['total'].')';
		$countries_div->addItem((new CSpan($label))->addClass('dgblk-country'));
	}
}

if ($data['error'] !== null) {
	$table = (new CTableInfo())->setNoDataMessage($data['error']);
} else {
	$table = (new CTableInfo())
		->setHeader([
			_('Origem'),
			_('Host protegido'),
			_('IP de origem'),
			_('Pais'),
			_('Ferramenta'),
			_('Regra / Assinatura'),
			_('Porta/Proto'),
			_('Motivo / Malware'),
			_('Horario'),
		]);

	if (!$data['blocks']) {
		$table->setNoDataMessage(_('Nenhum bloqueio registrado no periodo selecionado.'));
	}

	foreach ($data['blocks'] as $block) {
		$is_fw = $block['block_source'] === 'firewall';
		$origin = $is_fw
			? (new CSpan(_('Firewall')))->addClass('dgblk-fw')
			: (new CSpan(_('Antivirus')))->addClass('dgblk-av');

		$country = '';
		if ($block['country_code']) $country = $block['country_code'];
		if ($block['country_name']) $country .= ($country ? ' - ' : '').$block['country_name'];
		if (!$country) $country = '--';

		$port = $block['protocol']
			? $block['protocol'].'/'.($block['target_port'] ?? '-')
			: ($block['target_port'] ?? '-');

		$reason = $is_fw
			? ($block['reason'] ?: '--')
			: ($block['rule_or_signature'] ?: ($block['reason'] ?: '--'));

		$table->addRow([
			$origin,
			$block['host_name'] ?? '--',
			$block['src_ip'],
			$country,
			$block['tool'] ?: '--',
			$is_fw ? ($block['rule_or_signature'] ?: '--') : ($block['file_path'] ?: '--'),
			$port,
			$reason,
			date('d/m H:i:s', strtotime($block['event_time'])),
		]);
	}
}

(new CWidgetView($data))
	->addItem($style)
	->addItem((new CDiv())->addClass('dgblk')->addItem($cards)->addItem($countries_div))
	->addItem($table)
	->show();
