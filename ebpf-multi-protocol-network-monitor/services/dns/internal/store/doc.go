// Package store 提供 DNS baseline 的静态权威记录库。
//
// 它只负责按 QName + QType 做查找，不负责 DNS 报文解析、不负责响应编码，
// 这些工作分别由 dnsmsg 和 server 层完成。
package store
