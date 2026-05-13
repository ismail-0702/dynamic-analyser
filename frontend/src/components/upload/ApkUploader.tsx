import { UploadCloud } from 'lucide-react'
import { useRef, useState } from 'react'
import type { UploadResponse } from '../../types'

interface ApkUploaderProps {
  onUploaded: (response: UploadResponse) => void
}

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

export function ApkUploader({ onUploaded }: ApkUploaderProps) {
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [isDragging, setDragging] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const upload = (file: File) => {
    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('Only APK files are accepted')
      return
    }
    setError(null)
    setProgress(1)
    const form = new FormData()
    form.append('file', file)
    const request = new XMLHttpRequest()
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        setProgress(Math.round((event.loaded / event.total) * 100))
      }
    }
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) {
        onUploaded(JSON.parse(request.responseText) as UploadResponse)
      } else {
        setError(request.responseText || 'Upload failed')
      }
      setProgress(0)
    }
    request.onerror = () => {
      setError('Upload failed')
      setProgress(0)
    }
    request.open('POST', `${API_BASE_URL}/api/apk/upload`)
    request.send(form)
  }

  return (
    <section
      className={`border border-dashed ${isDragging ? 'border-brand bg-emerald-50' : 'border-line bg-white'} rounded-md p-4`}
      onDragLeave={() => setDragging(false)}
      onDragOver={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDrop={(event) => {
        event.preventDefault()
        setDragging(false)
        const file = event.dataTransfer.files.item(0)
        if (file) upload(file)
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <UploadCloud size={24} className="text-brand" />
          <div>
            <h2 className="text-base font-semibold text-ink">Upload APK</h2>
            <p className="text-sm text-slate-500">Static analysis runs immediately after upload.</p>
          </div>
        </div>
        <input
          ref={inputRef}
          accept=".apk"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.item(0)
            if (file) upload(file)
          }}
          type="file"
        />
        <button
          className="rounded-md bg-brand px-3 py-2 text-sm font-medium text-white"
          onClick={() => inputRef.current?.click()}
          type="button"
        >
          Select APK
        </button>
      </div>
      {progress > 0 && (
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200">
          <div className="h-full bg-brand transition-all" style={{ width: `${progress}%` }} />
        </div>
      )}
      {error && <div className="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}
    </section>
  )
}
