import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, RotateCcw } from 'lucide-react';
import { AttackChainRecord, AttackGraphNode } from '../api/client';

interface AttackChainGraphProps {
  chain: AttackChainRecord | null;
  heightClass?: string;
}

export const AttackChainGraph: React.FC<AttackChainGraphProps> = ({
  chain,
  heightClass = 'h-[480px]',
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    if (!chain || chain.nodes.length === 0) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      setSelectedNode(null);
      return;
    }

    const elements = [
      ...chain.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          nodeType: n.type,
          risk: n.risk,
        },
      })),
      ...chain.edges.map((e) => ({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-wrap': 'wrap',
            'text-max-width': '140px',
            'font-size': '11px',
            'font-family': 'IBM Plex Mono, monospace',
            color: '#F8FAFC',
            'text-valign': 'center',
            'text-halign': 'center',
            'background-color': '#1E293B',
            'border-width': 2,
            'border-color': '#475569',
            shape: 'round-rectangle',
            width: 155,
            height: 58,
            padding: '8px',
          },
        },
        {
          selector: 'node[risk = "CRITICAL"], node[risk = "BLOCKED"]',
          style: {
            'background-color': '#3B0D11',
            'border-color': '#EF4444',
            color: '#FEE2E2',
          },
        },
        {
          selector: 'node[risk = "HIGH"]',
          style: {
            'background-color': '#3B2106',
            'border-color': '#F59E0B',
            color: '#FEF3C7',
          },
        },
        {
          selector: 'node[risk = "SAFE"]',
          style: {
            'background-color': '#062E22',
            'border-color': '#10B981',
            color: '#D1FAE5',
          },
        },
        {
          selector: 'node[risk = "CONTAINED"]',
          style: {
            'background-color': '#0C2D48',
            'border-color': '#38BDF8',
            color: '#E0F2FE',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#F8FAFC',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#64748B',
            'target-arrow-color': '#64748B',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': '10px',
            'font-family': 'IBM Plex Mono, monospace',
            color: '#94A3B8',
            'text-background-color': '#0B0F19',
            'text-background-opacity': 0.85,
            'text-background-padding': '3px',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 32,
        spacingFactor: 1.15,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
    });

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      setSelectedNode({
        id: nodeData.id,
        label: nodeData.label,
        type: nodeData.nodeType,
        risk: nodeData.risk,
      });
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [chain]);

  const handleZoomIn = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    if (!cyRef.current) return;
    cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(undefined, 32);
  };

  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current.layout({ name: 'breadthfirst', directed: true, padding: 32, spacingFactor: 1.15 }).run();
    cyRef.current.fit(undefined, 32);
    setSelectedNode(null);
  };

  if (!chain || chain.nodes.length === 0) {
    return (
      <div className={`flex flex-col items-center justify-center ${heightClass} bg-[#0B0F19] border border-slate-800 rounded-lg p-6 text-center`}>
        <p className="text-sm font-medium text-slate-300">No correlated attack chains recorded</p>
        <p className="text-xs text-slate-500 mt-1 max-w-md">
          Attack chains are constructed dynamically from backend graph correlation when multi-step suspicious behavior or indirect prompt injection is intercepted.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col bg-[#0B0F19] border border-slate-800 rounded-lg overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#111827] border-b border-slate-800">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
          <span className="text-red-400 font-semibold">{chain.classification}</span>
          <span aria-hidden="true">·</span>
          <span>Chain ID: {chain.chain_id}</span>
          <span aria-hidden="true">·</span>
          <span>Agent: {chain.agent_id}</span>
          <span aria-hidden="true">·</span>
          <span>Status: {chain.status}</span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleZoomIn}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded transition-colors whitespace-nowrap"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
            <span>Zoom In</span>
          </button>
          <button
            type="button"
            onClick={handleZoomOut}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded transition-colors whitespace-nowrap"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
            <span>Zoom Out</span>
          </button>
          <button
            type="button"
            onClick={handleFit}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded transition-colors whitespace-nowrap"
            title="Fit to Viewport"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Fit</span>
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded transition-colors whitespace-nowrap"
            title="Reset Graph Layout"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      <div className="relative">
        <div ref={containerRef} className={`w-full ${heightClass}`} />

        {selectedNode && (
          <div className="absolute bottom-3 left-3 right-3 md:right-auto md:w-80 bg-[#111827]/95 border border-slate-700 rounded-md p-3.5 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
              <span className="text-xs font-mono font-semibold text-slate-200">
                Selected Node Inspector
              </span>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-xs text-slate-400 hover:text-white"
              >
                Close
              </button>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Node ID:</span>
                <span className="text-slate-200">{selectedNode.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Entity Type:</span>
                <span className="text-sky-400 uppercase">{selectedNode.type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Risk State:</span>
                <span
                  className={
                    selectedNode.risk === 'CRITICAL' || selectedNode.risk === 'BLOCKED'
                      ? 'text-red-400 font-semibold'
                      : selectedNode.risk === 'HIGH'
                      ? 'text-amber-400 font-semibold'
                      : 'text-emerald-400 font-semibold'
                  }
                >
                  {selectedNode.risk}
                </span>
              </div>
              <div className="pt-1 text-slate-300 whitespace-pre-line">
                {selectedNode.label}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
