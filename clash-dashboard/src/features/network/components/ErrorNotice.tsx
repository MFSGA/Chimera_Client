import { AlertTriangle } from 'lucide-react';

export function ErrorNotice({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-xl p-3 text-[13px]"
      style={{ background: 'rgba(255,59,48,0.08)', border: '1px solid rgba(255,59,48,0.2)', color: '#ff3b30' }}
    >
      <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
      <span>{message}</span>
    </div>
  );
}
