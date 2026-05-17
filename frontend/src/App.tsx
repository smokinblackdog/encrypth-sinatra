import { useMemo, useState } from 'react'
import {
  Alert,
  Badge,
  Button,
  CloseButton,
  Divider,
  Group,
  List,
  Paper,
  Popover,
  PasswordInput,
  Stack,
  Text,
  Title,
  Flex,
  LoadingOverlay,
  Tabs,
} from '@mantine/core'
import { Dropzone, type FileWithPath } from '@mantine/dropzone'
import axios from 'axios'
import './App.css'

const MAX_FILES = 10
const API_URL = 'http://localhost:4567'

const api = axios.create({
  baseURL: API_URL,
  timeout: 120000,
})

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function fileKey(file: File) {
  return `${file.name}-${file.size}-${file.lastModified}`
}

function App() {
  // Состояния для шифрования
  const [files, setFiles] = useState<File[]>([])
  const [password, setPassword] = useState('')
  const [limitMessage, setLimitMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Состояния для расшифровки
  const [decryptFile, setDecryptFile] = useState<File | null>(null)
  const [decryptPassword, setDecryptPassword] = useState('')
  const [decryptLoading, setDecryptLoading] = useState(false)
  const [decryptError, setDecryptError] = useState('')
  const [decryptSuccess, setDecryptSuccess] = useState('')

  const totalSize = useMemo(
    () => files.reduce((sum, file) => sum + file.size, 0),
    [files],
  )

  const addFiles = (incoming: FileWithPath[]) => {
    setFiles((current) => {
      const seen = new Set(current.map(fileKey))
      const merged = [...current]

      for (const file of incoming) {
        const key = fileKey(file)
        if (seen.has(key)) continue
        if (merged.length >= MAX_FILES) break
        merged.push(file)
        seen.add(key)
      }

      if (current.length + incoming.length > MAX_FILES || merged.length === MAX_FILES) {
        setLimitMessage(`Вы можете загрузить до ${MAX_FILES} файлов.`)
      } else {
        setLimitMessage('')
      }

      return merged
    })

    setPassword('')
    setError('')
    setSuccess('')
  }

  const removeFile = (keyToRemove: string) => {
    setFiles((current) => current.filter((file) => fileKey(file) !== keyToRemove))
    setPassword('')
    setLimitMessage('')
    setError('')
    setSuccess('')
  }

  const clearFiles = () => {
    setFiles([])
    setPassword('')
    setLimitMessage('')
    setError('')
    setSuccess('')
  }

  const handleEncrypt = async () => {
    if (!password.trim()) {
      setError('Введите пароль')
      return
    }

    if (password.length < 8) {
      setError('Пароль должен быть минимум 8 символов')
      return
    }

    if (files.length === 0) {
      setError('Выберите файлы для шифрования')
      return
    }

    setLoading(true)
    setError('')
    setSuccess('')

    const formData = new FormData()
    files.forEach(file => {
      formData.append('files[]', file)
    })
    formData.append('password', password)

    try {
      const response = await api.post('/upload', formData, {
        responseType: 'blob',
      })

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `secure_archive_${Date.now()}.tar.enc`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      setSuccess('Файлы успешно зашифрованы и скачаны!')
      setFiles([])
      setPassword('')
      
    } catch (err) {
      if (axios.isAxiosError(err)) {
        if (err.response?.status === 400) {
          try {
            const errorData = JSON.parse(await err.response.data.text())
            setError(errorData.error || 'Ошибка валидации')
          } catch {
            setError('Недопустимый формат файла или превышен лимит')
          }
        } else if (err.response?.status === 413) {
          setError('Файл слишком большой. Максимальный размер 100 MB')
        } else if (err.response?.status === 429) {
          setError('Слишком много запросов. Подождите минуту')
        } else if (err.code === 'ECONNABORTED') {
          setError('Превышено время ожидания. Сервер перегружен или файлы слишком большие')
        } else {
          setError(err.message || 'Ошибка при шифровании')
        }
      } else {
        setError('Произошла неизвестная ошибка')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleDecrypt = async () => {
    if (!decryptFile) {
      setDecryptError('Выберите файл для расшифровки')
      return
    }

    if (!decryptPassword || decryptPassword.length < 8) {
      setDecryptError('Пароль должен быть минимум 8 символов')
      return
    }

    setDecryptLoading(true)
    setDecryptError('')
    setDecryptSuccess('')

    const formData = new FormData()
    formData.append('file', decryptFile)
    formData.append('password', decryptPassword)

    try {
      const response = await api.post('/decrypt', formData, {
        responseType: 'blob',
      })

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `decrypted_${Date.now()}.zip`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      setDecryptSuccess('Файлы успешно расшифрованы и скачаны!')
      setDecryptFile(null)
      setDecryptPassword('')
      
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 400) {
        try {
          const errorData = JSON.parse(await err.response.data.text())
          setDecryptError(errorData.error || 'Неверный пароль или файл повреждён')
        } catch {
          setDecryptError('Неверный пароль или файл повреждён')
        }
      } else {
        setDecryptError('Ошибка при расшифровке')
      }
    } finally {
      setDecryptLoading(false)
    }
  }

  return (
    <main className="upload-stage">
      <Paper className="upload-window" p="xl" radius="md" withBorder>
        <LoadingOverlay visible={loading || decryptLoading} />

        <Stack gap="lg">
          <Group justify="space-between" align="center">
            <Title order={2} className='text'>Защищённое шифрование файлов</Title>

            <Badge 
              component='a'
              href='https://github.com/smokinblackdog/encrypth'
              target='_blank'
              style={{ 
                cursor: 'pointer',
                background: 'var(--accent)'
              }}
            >
              ENCRYPTH
            </Badge>
          </Group>

          <Tabs color='#bf78ff' defaultValue="encrypt">
            <Tabs.List>
              <Tabs.Tab value="encrypt"><span className='tabs'>Зашифровать</span></Tabs.Tab>
              <Tabs.Tab value="decrypt"><span className='tabs'>Расшифровать</span></Tabs.Tab>
            </Tabs.List>

            {/* Вкладка шифрования */}
            <Tabs.Panel value="encrypt" pt="lg">
              <Stack gap="lg">
                <Dropzone
                  onDrop={addFiles}
                  onReject={(rejections) => {
                    const hasInvalidFormat = rejections.some(rejection => 
                      rejection.errors.some(error => error.code === 'file-invalid-type')
                    );
                    if (hasInvalidFormat) {
                      setLimitMessage('Недопустимый формат. Разрешены: JPG, PNG, GIF, PDF, DOCX, TXT, CSV, MP3, MP4, ZIP.');
                    } else {
                      setLimitMessage('Файл не загружен. Возможно, превышен размер или нарушены другие ограничения.');
                    }
                  }}
                  accept={{
                    'image/jpeg': ['.jpg', '.jpeg'],
                    'image/png': ['.png'],
                    'image/gif': ['.gif'],
                    'image/bmp': ['.bmp'],
                    'image/webp': ['.webp'],
                    'application/pdf': ['.pdf'],
                    'application/msword': ['.doc'],
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
                    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
                    'text/plain': ['.txt', '.csv', '.log', '.md'],
                    'application/json': ['.json', '.xml'],
                    'audio/*': ['.mp3', '.wav', '.ogg', '.flac'],
                    'video/*': ['.mp4'],
                    'application/zip': ['.zip']
                  }}
                  className="dropzone"
                  multiple
                  disabled={loading}
                >
                  <Stack gap={4} align="center">
                    <Text fw={600}>Бросьте файлы сюда</Text>
                    <Text size="sm" className='text-muted'>
                      или кликните для загрузки ({files.length}/{MAX_FILES})
                    </Text>
                  </Stack>
                </Dropzone>

                <Popover width={300} position="bottom-end">
                  <Popover.Target>
                    <Button
                      variant='transparent'
                      size='compact-sm'
                      style={{
                        color: 'var(--text-muted)',
                        alignSelf: 'end',
                        width: '200px',
                        marginTop: '-5px'
                      }}
                      disabled={loading}
                    >
                      О допустимых форматах
                    </Button>
                  </Popover.Target>
                  <Popover.Dropdown bg={'#12101a'} c='white'>
                    <List listStyleType="disc">
                      <List.Item>
                        Принимаются: JPG, PNG, GIF, BMP, WebP, PDF, DOCX, XLSX, PPTX, TXT, CSV, JSON, XML, MD, LOG, MP3, MP4, WAV, OGG, FLAC, ZIP
                      </List.Item>
                      <List.Item>
                        Не принимаются: EXE, MSI, SCR, JS, HTML, SVG, BAT, PS1
                      </List.Item>
                    </List>
                    <Text size="xs" mt="sm">
                      Запрещённые файлы можно упаковать в ZIP — но такие архивы могут быть опасны для получателя
                    </Text>
                  </Popover.Dropdown>
                </Popover>

                {limitMessage && (
                  <Alert color="violet" variant="light">
                    {limitMessage}
                  </Alert>
                )}

                {error && (
                  <Alert color="red" variant="light" onClose={() => setError('')} withCloseButton>
                    {error}
                  </Alert>
                )}

                {success && (
                  <Alert color="green" variant="light" onClose={() => setSuccess('')} withCloseButton>
                    {success}
                  </Alert>
                )}

                {files.length > 0 && (
                  <>
                    <Divider my="5" />
                    <Stack gap="sm">
                      <Group justify="space-between" align="center">
                        <Text className='text' fw={600}>Выбранные файлы ({files.length}/{MAX_FILES})</Text>
                        <Button 
                          size="xs" 
                          variant="filled" 
                          onClick={clearFiles}
                          color="rgba(207, 56, 66, 1)"
                          disabled={loading}
                        >
                          Удалить все
                        </Button>
                      </Group>

                      <Stack gap="xs" className="file-list">
                        {files.map((file) => {
                          const key = fileKey(file)
                          return (
                            <Group key={key} justify="space-between" className="file-item">
                              <div>
                                <Text className='text' size="sm">{file.name}</Text>
                                <Text size="xs" className='text-muted'>
                                  {formatSize(file.size)}
                                </Text>
                              </div>
                              <CloseButton
                                variant='transparent'
                                aria-label={`Удалить ${file.name}`}
                                onClick={() => removeFile(key)}
                                disabled={loading}
                              />
                            </Group>
                          )
                        })}
                      </Stack>

                      <Text size="sm" className='text-muted'>
                        Общий размер: {formatSize(totalSize)}
                      </Text>
                    </Stack>
                  </>
                )}
                
                {files.length > 0 && (
                  <Flex gap="sm" direction="row" wrap="wrap-reverse">
                    <PasswordInput
                      label="Пароль"
                      placeholder="Введите пароль (минимум 8 символов)"
                      value={password}
                      onChange={(event) => setPassword(event.currentTarget.value)}
                      className='text'
                      style={{ flex: 1 }}
                      disabled={loading}
                      error={password && password.length < 8 ? 'Минимум 8 символов' : false}
                    />
                    <Button 
                      color="violet" 
                      onClick={handleEncrypt}
                      disabled={!password.trim() || password.length < 8 || loading}
                      loading={loading}
                    >
                      Зашифровать и скачать
                    </Button>
                  </Flex>
                )}
              </Stack>
            </Tabs.Panel>

            {/* Вкладка расшифровки */}
            <Tabs.Panel value="decrypt" pt="lg">
              <Stack gap="lg">
                <Dropzone
                  onDrop={(files) => setDecryptFile(files[0])}
                  onReject={(rejections) => {
                    const message = rejections[0]?.errors[0]?.message || 'Файл отклонен';
                    setDecryptError(message);
                    setDecryptFile(null);
                  }}    
                  validator={
                    (file: File) => 
                      {
                        if (!file.name.endsWith('.tar.enc')) 
                          return {
                            code: 'invalid-extension',
                            message: 'Разрешены только файлы .tar.enc',
                          }; 
                          return null
                        }
                      }
                  accept={{ 'application/octet-stream': ['.tar.enc'] }}
                  maxFiles={1}
                  disabled={decryptLoading}
                  className="dropzone"
                >
                  <Stack gap={4} align="center">
                    <Text fw={600}>
                      {decryptFile ? decryptFile.name : 'Бросьте .tar.enc файл сюда'}
                    </Text>
                    <Text size="sm" className='text-muted'>
                      или кликните для выбора
                    </Text>
                  </Stack>
                </Dropzone>

                {decryptError && (
                  <Alert color="red" variant="light" onClose={() => setDecryptError('')} withCloseButton>
                    {decryptError}
                  </Alert>
                )}

                {decryptSuccess && (
                  <Alert color="green" variant="light" onClose={() => setDecryptSuccess('')} withCloseButton>
                    {decryptSuccess}
                  </Alert>
                )}

                {decryptFile && (
                  <Flex gap="sm" direction="row" wrap="wrap-reverse">
                    <PasswordInput
                      label="Пароль"
                      placeholder="Введите пароль от архива (минимум 8 символов)"
                      value={decryptPassword}
                      onChange={(event) => setDecryptPassword(event.currentTarget.value)}
                      className='text'
                      style={{ flex: 1 }}
                      disabled={decryptLoading}
                      error={decryptPassword && decryptPassword.length < 8 ? 'Минимум 8 символов' : false}
                    />
                    <Button 
                      color="green" 
                      onClick={handleDecrypt}
                      disabled={!decryptPassword || decryptPassword.length < 8 || decryptLoading}
                      loading={decryptLoading}
                    >
                      Расшифровать и скачать
                    </Button>
                  </Flex>
                )}
              </Stack>
            </Tabs.Panel>
          </Tabs>
        </Stack>
      </Paper>
    </main>
  )
}

export default App