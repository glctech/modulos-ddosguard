<?php declare(strict_types = 0);
/**
 * DDoS Guard - Response Timeline - view
 * @var CView $this
 * @var array $data
 */
$incidents = $data['incidents'];
$stats     = $data['stats'];
$sc = ['critical'=>'#d63939','high'=>'#f0a30a','medium'=>'#4b8cb8','low'=>'#2fa84f','info'=>'#999'];

$style = (new CTag('style', true))->addItem('
	.dgtl { display: flex; flex-direction: column; gap: 6px; height: 100%; font-size: 12px; }
	.dgtl-header { display: flex; justify-content: space-between; align-items: center; }
	.dgtl-title { font-size: 10px; font-weight: 700; }
	.dgtl-stats { display: flex; gap: 10px; }
	.dgtl-stat { display: flex; flex-direction: column; align-items: center; }
	.dgtl-stat-val { font-size: 14px; font-weight: 700; font-family: monospace; }
	.dgtl-stat-lbl { font-size: 8px; text-transform: uppercase; letter-spacing: .06em; color: #999; }
	.dgtl-list { display: flex; flex-direction: column; gap: 4px; overflow-y: auto; flex: 1; }
	.dgtl-list::-webkit-scrollbar { width: 3px; }
	.dgtl-list::-webkit-scrollbar-thumb { background: rgba(128,128,128,.3); border-radius: 2px; }
	.dgtl-item { display: flex; align-items: center; gap: 6px; padding: 5px 8px;
		border-radius: 3px; border: 1px solid rgba(128,128,128,.1); background: rgba(128,128,128,.03); }
	.dgtl-bar { width: 3px; height: 26px; border-radius: 2px; flex-shrink: 0; }
	.dgtl-main { flex: 1; min-width: 0; }
	.dgtl-type { font-size: 10px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dgtl-meta { font-size: 9px; color: #999; margin-top: 1px; }
	.dgtl-right { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; flex-shrink: 0; }
	.dgtl-score { font-size: 9px; font-weight: 700; font-family: monospace; padding: 1px 5px; border-radius: 2px; }
	.dgtl-dur { font-size: 9px; font-family: monospace; color: #999; }
	.dgtl-tech { font-size: 8px; font-family: monospace; padding: 1px 4px; border-radius: 2px;
		background: rgba(155,89,182,.12); color: #9b59b6; }
	.dgtl-empty { color: #999; font-size: 10px; padding: 16px; text-align: center; }
');

// Stats header — todos os quatro valores vêm de dados reais (nada
// decorativo). O sistema não tem, hoje, uma métrica confiável de tempo
// de detecção/resposta (exigiria saber quando o ataque realmente
// começou, não só quando foi registrado) — por isso o cabeçalho mostra
// volume real em vez de inventar um MTTD/MTTA/MTTM.
$stats_div = (new CDiv())->addClass('dgtl-stats');
foreach ([
	[(int) ($stats['total'] ?? 0),   '#d63939', _('Eventos 24h')],
	[(int) ($stats['ips'] ?? 0),     '#f0a30a', _('IPs 24h')],
	[(int) ($stats['max_att'] ?? 0), '#4b8cb8', _('Pico tentativas')],
	[count($incidents),              '#9b59b6', _('Incidentes 7d')],
] as [$v, $c, $l]) {
	$stats_div->addItem(
		(new CDiv())
			->addClass('dgtl-stat')
			->addItem((new CDiv($v))->addClass('dgtl-stat-val')->addStyle("color:$c"))
			->addItem((new CDiv($l))->addClass('dgtl-stat-lbl'))
	);
}

// Incident list
$list = (new CDiv())->addClass('dgtl-list');
if ($incidents) {
	foreach ($incidents as $inc) {
		$sev   = $inc['severity_label'] ?? 'info';
		$color = $sc[$sev] ?? '#999';
		$score = (int)($inc['severity_score'] ?? 0);
		$dur   = (int)($inc['duration_min']   ?? 0);
		$ds    = $dur < 60 ? $dur.'m' : round($dur/60,1).'h';
		$country = !empty($inc['country_name']) ? ' - '.htmlspecialchars($inc['country_name']) : '';
		$tech_item = !empty($inc['mitre_technique'])
			? (new CDiv(htmlspecialchars($inc['mitre_technique'])))->addClass('dgtl-tech')
			: new CDiv();

		$list->addItem(
			(new CDiv())
				->addClass('dgtl-item')
				->addItem((new CDiv())->addClass('dgtl-bar')->addStyle("background:$color"))
				->addItem(
					(new CDiv())
						->addClass('dgtl-main')
						->addItem((new CDiv(htmlspecialchars(str_replace('_',' ',$inc['attack_type']??'')).' - '.htmlspecialchars($inc['host']??$inc['src_ip']??'')))->addClass('dgtl-type'))
						->addItem((new CDiv(htmlspecialchars($inc['src_ip']??'').$country.' - '.(int)($inc['attempts']??0).' tent. - '.date('d/m H:i',strtotime($inc['last_seen']??'now'))))->addClass('dgtl-meta'))
				)
				->addItem(
					(new CDiv())
						->addClass('dgtl-right')
						->addItem((new CDiv($score.'/10'))->addClass('dgtl-score')->addStyle("background:{$color}22;color:{$color}"))
						->addItem((new CDiv($ds))->addClass('dgtl-dur'))
						->addItem($tech_item)
				)
		);
	}
} else {
	$list->addItem((new CDiv(_('Nenhum incidente nos ultimos 7 dias')))->addClass('dgtl-empty'));
}

(new CWidgetView($data))
	->addItem($style)
	->addItem(
		(new CDiv())
			->addClass('dgtl')
			->addItem(
				(new CDiv())
					->addClass('dgtl-header')
					->addItem((new CDiv(_('Incidentes - 7 dias (score >= 3)')))->addClass('dgtl-title'))
					->addItem($stats_div)
			)
			->addItem($list)
	)
	->show();
