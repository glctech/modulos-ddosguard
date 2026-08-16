<?php declare(strict_types = 0);
/**
 * DDoS Guard - SOC Overview - view
 * @var CView $this
 * @var array $data
 */
$kpis        = $data['kpis'];
$alerts      = $data['alerts'];
$hosts       = $data['hosts'];
$stale_count = $data['stale_count'];
$sc = ['critical'=>'#d63939','high'=>'#f0a30a','medium'=>'#4b8cb8','low'=>'#2fa84f','info'=>'#999'];

$range_labels = [60=>_('última hora'), 360=>_('últimas 6h'), 1440=>_('últimas 24h'), 10080=>_('últimos 7 dias')];
$range_label = $range_labels[$data['time_range']] ?? _s('últimos %1$d min', $data['time_range']);

$style = (new CTag('style', true))->addItem('
	.dgsoc { display: flex; flex-direction: column; gap: 8px; }
	.dgsoc-kpis { display: flex; gap: 6px; flex-wrap: wrap; }
	.dgsoc-kpi { flex: 1; min-width: 90px; background: rgba(128,128,128,.07);
		border-radius: 4px; padding: 8px 10px; border-top: 2px solid #ccc; }
	.dgsoc-kpi-label { font-size: 9px; text-transform: uppercase; color: #999;
		margin-bottom: 3px; letter-spacing: .06em; }
	.dgsoc-kpi-value { font-size: 22px; font-weight: 700; line-height: 1; }
	.dgsoc-kpi-sub { font-size: 10px; color: #999; margin-top: 2px; }
	.dgsoc-status { display: flex; align-items: center; gap: 8px; border-radius: 4px;
		padding: 8px 12px; border: 1px solid rgba(128,128,128,.12); }
	.dgsoc-status-ok { background: rgba(47,168,79,.08); border-color: rgba(47,168,79,.3); }
	.dgsoc-status-warn { background: rgba(214,57,57,.08); border-color: rgba(214,57,57,.3); }
	.dgsoc-status-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
	.dgsoc-status-text { font-size: 11px; font-weight: 600; }
	.dgsoc-status-sub { font-size: 10px; color: #999; margin-left: auto; }
	.dgsoc-bottom { display: flex; gap: 8px; }
	.dgsoc-alerts, .dgsoc-hosts { flex: 1; background: rgba(128,128,128,.04);
		border: 1px solid rgba(128,128,128,.1); border-radius: 4px; padding: 8px 10px; min-height: 60px; }
	.dgsoc-box-title { font-size: 10px; font-weight: 700; margin-bottom: 6px; color: #999;
		text-transform: uppercase; letter-spacing: .05em; }
	.dgsoc-alert-item { display: flex; gap: 6px; padding: 4px 0;
		border-bottom: 1px solid rgba(128,128,128,.07); align-items: flex-start; }
	.dgsoc-alert-item:last-child { border-bottom: none; }
	.dgsoc-alert-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; margin-top: 3px; }
	.dgsoc-alert-type { font-size: 10px; font-weight: 500; }
	.dgsoc-alert-meta { font-size: 9px; color: #999; margin-top: 1px; }
	.dgsoc-alert-time { font-size: 9px; font-family: monospace; color: #999; margin-left: auto; flex-shrink: 0; }
	.dgsoc-host-item { display: flex; align-items: center; gap: 6px;
		padding: 3px 0; border-bottom: 1px solid rgba(128,128,128,.07); font-size: 10px; }
	.dgsoc-host-item:last-child { border-bottom: none; }
	.dgsoc-host-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
	.dgsoc-host-name { flex: 1; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dgsoc-host-status { font-size: 9px; color: #999; }
	.dgsoc-empty { color: #999; font-size: 10px; padding: 6px 0; }
');

// ---------------------------------------------------------------------
// Status geral do pipeline - único indicador "executivo" no topo:
// substitui o antigo bloco de timeline decorativo (valores fixos que
// nunca refletiam o estado real). Aqui, tudo é derivado do heartbeat
// real dos hosts.
// ---------------------------------------------------------------------
$total_hosts = count($hosts);
$healthy = $total_hosts - $stale_count;
if ($total_hosts === 0) {
	$status_class = 'dgsoc-status-warn';
	$status_text = _('Nenhum host enviando dados ao DDoS Guard');
	$status_sub = _('Verifique a instalação do agente/integrações');
}
elseif ($stale_count === 0) {
	$status_class = 'dgsoc-status-ok';
	$status_text = _s('Monitoramento ativo — %1$d/%2$d hosts íntegros', $healthy, $total_hosts);
	$status_sub = _s('Heartbeat OK em todos os hosts (%1$s)', $range_label);
}
else {
	$status_class = 'dgsoc-status-warn';
	$status_text = _s('Atenção — %1$d de %2$d hosts sem heartbeat recente', $stale_count, $total_hosts);
	$status_sub = _('Pipeline pode estar parado nesses hosts — verifique o agente');
}
$status_div = (new CDiv())
	->addClass('dgsoc-status '.$status_class)
	->addItem((new CDiv())->addClass('dgsoc-status-dot')->addStyle('background:'.($status_class === 'dgsoc-status-ok' ? '#2fa84f' : '#d63939')))
	->addItem((new CDiv($status_text))->addClass('dgsoc-status-text'))
	->addItem((new CDiv($status_sub))->addClass('dgsoc-status-sub'));

// KPIs — todos os quatro refletem a mesma janela de tempo configurada
// no widget (exceto Críticos, que é o estado atual de correlações
// abertas, não uma contagem por período).
$kpi_div = (new CDiv())->addClass('dgsoc-kpis');
foreach ([
	['Eventos', $kpis['events'], $kpis['ips'].' '._('IPs distintos').' - '.$range_label, '#d63939'],
	['Tentativas', number_format((int) $kpis['attempts'], 0, ',', '.'), $range_label, '#f0a30a'],
	['Bloqueados', number_format((int) $kpis['blocks'], 0, ',', '.'), $range_label, '#2fa84f'],
	['Críticos', $kpis['critical'], _('correlações abertas, score >= 7'), '#9b59b6'],
] as [$lbl, $val, $sub, $color]) {
	$kpi_div->addItem(
		(new CDiv())
			->addClass('dgsoc-kpi')
			->addStyle("border-top-color:$color")
			->addItem((new CDiv($lbl))->addClass('dgsoc-kpi-label'))
			->addItem((new CDiv($val))->addClass('dgsoc-kpi-value')->addStyle("color:$color"))
			->addItem((new CDiv($sub))->addClass('dgsoc-kpi-sub'))
	);
}

// Alertas
$alerts_box = (new CDiv())->addClass('dgsoc-alerts')
	->addItem((new CDiv(_s('Alertas recentes (%1$s)', $range_label)))->addClass('dgsoc-box-title'));
if ($alerts) {
	foreach (array_slice($alerts, 0, 4) as $a) {
		$color = $sc[$a['severity_label'] ?? 'info'] ?? '#999';
		$alerts_box->addItem(
			(new CDiv())
				->addClass('dgsoc-alert-item')
				->addItem((new CDiv())->addClass('dgsoc-alert-dot')->addStyle("background:$color"))
				->addItem(
					(new CDiv())
						->addStyle('flex:1;min-width:0')
						->addItem((new CDiv(htmlspecialchars(str_replace('_', ' ', $a['attack_type'] ?? ''))))->addClass('dgsoc-alert-type'))
						->addItem((new CDiv(htmlspecialchars($a['src_ip'] ?? '').' - '.htmlspecialchars($a['host'] ?? '')))->addClass('dgsoc-alert-meta'))
				)
				->addItem((new CDiv(date('H:i', strtotime($a['last_seen'] ?? 'now'))))->addClass('dgsoc-alert-time'))
		);
	}
}
else {
	$alerts_box->addItem((new CDiv(_s('Nenhum evento nas %1$s', $range_label)))->addClass('dgsoc-empty'));
}

// Hosts
$hosts_box = (new CDiv())->addClass('dgsoc-hosts')
	->addItem((new CDiv(_('Hosts').' ('.count($hosts).')'))->addClass('dgsoc-box-title'));
if ($hosts) {
	foreach (array_slice($hosts, 0, 5) as $h) {
		if ($h['online']) {
			$status_label = _('OK');
		}
		elseif ($h['last_heartbeat'] > 0) {
			$mins = (int) round($h['age_seconds'] / 60);
			$status_label = $mins < 60
				? _s('há %1$dmin', $mins)
				: _s('há %1$dh', (int) round($mins / 60));
		}
		else {
			$status_label = _('nunca');
		}
		$hosts_box->addItem(
			(new CDiv())
				->addClass('dgsoc-host-item')
				->addItem((new CDiv())->addClass('dgsoc-host-dot')->addStyle('background:'.($h['online'] ? '#2fa84f' : '#d63939')))
				->addItem((new CDiv(htmlspecialchars($h['host'] ?? '')))->addClass('dgsoc-host-name'))
				->addItem((new CDiv($status_label))->addClass('dgsoc-host-status'))
		);
	}
}
else {
	$hosts_box->addItem((new CDiv(_('Nenhum host encontrado')))->addClass('dgsoc-empty'));
}

(new CWidgetView($data))
	->addItem($style)
	->addItem($status_div)
	->addItem($kpi_div)
	->addItem((new CDiv())->addClass('dgsoc-bottom')->addItem($alerts_box)->addItem($hosts_box))
	->show();
