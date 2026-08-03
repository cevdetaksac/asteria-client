import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { t } from '../i18n'

export type DataColumn<T> = {
  id: string
  header: ReactNode
  cell: (row: T, index: number) => ReactNode
  className?: string
  headerClassName?: string
  /** Text used for client-side search (defaults to empty = not searchable). */
  searchText?: (row: T) => string
}

type Props<T> = {
  rows: T[]
  columns: DataColumn<T>[]
  rowKey: (row: T, index: number) => string
  empty?: ReactNode
  searchPlaceholder?: string
  defaultPageSize?: number
  pageSizeOptions?: number[]
  className?: string
  tableClassName?: string
  toolbarEnd?: ReactNode
  /** Hide search when list is always tiny. */
  searchable?: boolean
}

const DEFAULT_SIZES = [10, 25, 50, 100]

export function DataTable<T>({
  rows,
  columns,
  rowKey,
  empty,
  searchPlaceholder,
  defaultPageSize = 25,
  pageSizeOptions = DEFAULT_SIZES,
  className = '',
  tableClassName = '',
  toolbarEnd,
  searchable = true,
}: Props<T>) {
  const [query, setQuery] = useState('')
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [page, setPage] = useState(0)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((row) =>
      columns.some((col) => {
        const text = col.searchText?.(row)
        return text ? text.toLowerCase().includes(q) : false
      }),
    )
  }, [rows, columns, query])

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize) || 1)
  const safePage = Math.min(page, pageCount - 1)
  const start = safePage * pageSize
  const slice = filtered.slice(start, start + pageSize)
  const showingFrom = filtered.length === 0 ? 0 : start + 1
  const showingTo = Math.min(start + pageSize, filtered.length)

  useEffect(() => {
    if (safePage !== page) setPage(safePage)
  }, [safePage, page])

  return (
    <div className={`datatable ${className}`.trim()}>
      <div className="datatable-toolbar">
        {searchable ? (
          <input
            type="search"
            className="datatable-search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setPage(0)
            }}
            placeholder={searchPlaceholder || t('dt_search')}
            aria-label={searchPlaceholder || t('dt_search')}
          />
        ) : (
          <span />
        )}
        <div className="datatable-toolbar-end">
          {toolbarEnd}
          <label className="datatable-pagesize">
            <span className="muted">{t('dt_page_size')}</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value) || 25)
                setPage(0)
              }}
            >
              {pageSizeOptions.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="table-wrap datatable-wrap">
        <table className={tableClassName}>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.id} className={col.headerClassName}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="empty">
                  {empty ?? t('dt_empty')}
                </td>
              </tr>
            )}
            {slice.map((row, i) => {
              const abs = start + i
              return (
                <tr key={rowKey(row, abs)}>
                  {columns.map((col) => (
                    <td key={col.id} className={col.className}>
                      {col.cell(row, abs)}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div className="datatable-footer">
        <span className="muted">
          {t('dt_showing', { from: showingFrom, to: showingTo, total: filtered.length })}
        </span>
        <div className="datatable-pager">
          <button
            type="button"
            className="btn ghost sm"
            disabled={safePage <= 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            {t('dt_prev')}
          </button>
          <span className="datatable-page-label">
            {t('dt_page', { page: safePage + 1, pages: pageCount })}
          </span>
          <button
            type="button"
            className="btn ghost sm"
            disabled={safePage >= pageCount - 1}
            onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
          >
            {t('dt_next')}
          </button>
        </div>
      </div>
    </div>
  )
}
