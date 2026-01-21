import React from 'react';
import './UrlComponentsCard.css';

const UrlComponentsCard = ({ analysis }) => {
  if (!analysis) return null;
  const { tokens, hostname_components } = analysis;

  // Inline SVG Icons
  const icons = {
    Schema: (
      <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    Subdomain: (
      <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
      </svg>
    ),
    Domain: (
      <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
    TLD: (
      <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 21v-8a2 2 0 012-2h14a2 2 0 012 2v8M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    Path: (
      <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
      </svg>
    ),
  };

  const rows = [
    tokens?.schema && { label: 'Schema', value: tokens.schema, colorClass: 'badge-green' },
    hostname_components?.subdomain && { label: 'Subdomain', value: hostname_components.subdomain, colorClass: 'badge-yellow' },
    hostname_components?.domain && { label: 'Domain', value: hostname_components.domain, colorClass: 'badge-purple' },
    hostname_components?.tld && { label: 'TLD', value: hostname_components.tld, colorClass: 'badge-blue' },
    tokens?.path && { label: 'Path', value: tokens.path, colorClass: 'badge-red' },
  ].filter(Boolean);

  return (
    <div className="tokenizer-dfa-card">
      <div className="card-header">
        <h3 className="card-title">Tokenizer DFA Output</h3>
      </div>
      
      <div className="table-container">
        <table className="dfa-table">
          <thead>
            <tr>
              {/* FIX: 'w-1 whitespace-nowrap' forces this column to shrink to fit text */}
              <th className="w-1 whitespace-nowrap pl-6 pr-8 py-3 text-left text-xs font-bold uppercase tracking-wider text-gray-500">
                Component
              </th>
              {/* FIX: 'w-auto' lets this column take the remaining space naturally */}
              <th className="w-auto pl-0 py-3 text-left text-xs font-bold uppercase tracking-wider text-gray-500">
                Extracted Value
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={row.label} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                {/* FIX: Added padding-right (pr-8) to create the fixed gap you want */}
                <td className="w-1 whitespace-nowrap pl-6 pr-8 py-3 font-semibold text-gray-700">
                  <div className="flex items-center gap-3">
                    <span className="icon-wrapper">
                      {icons[row.label] || icons['Path']}
                    </span>
                    {row.label}
                  </div>
                </td>
                <td className="w-auto pl-0 py-3 text-left">
                  <span className={`token-badge ${row.colorClass}`}>
                    {row.value}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default UrlComponentsCard;