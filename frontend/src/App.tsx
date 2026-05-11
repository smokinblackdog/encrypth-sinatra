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
} from '@mantine/core'
import { Dropzone, type FileWithPath } from '@mantine/dropzone'
import './App.css'

const MAX_FILES = 10

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function fileKey(file: File) {
  return `${file.name}-${file.size}-${file.lastModified}`
}

function App() {
  const [files, setFiles] = useState<File[]>([])
  const [password, setPassword] = useState('')
  const [limitMessage, setLimitMessage] = useState('')

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
        setLimitMessage(`You can upload up to ${MAX_FILES} files.`)
      } else {
        setLimitMessage('')
      }

      return merged
    })

    setPassword('')
  }

  const removeFile = (keyToRemove: string) => {
    setFiles((current) => current.filter((file) => fileKey(file) !== keyToRemove))
    setPassword('')
    setLimitMessage('')
  }

  const clearFiles = () => {
    setFiles([])
    setPassword('')
    setLimitMessage('')
  }

  return (
    <main className="upload-stage">
      <Paper className="upload-window" p="xl" radius="md" withBorder>
        <Stack gap="lg">
          <Group justify="space-between" align="center">

            <Title order={2} className='text'>Защищённое шифрование файлов</Title>

            {/* полиморфный бейдж, при клике открывает репозиторий гема в новом окне и перенаправляет туда */}
            <Badge 
              component='a'
              href='https://github.com/smokinblackdog/encrypth'
              target='blank'
              style={{ 
                cursor: 'pointer',
                background: 'var(--accent)'
               }}
            >
              ENCRYPTH
            </Badge>
          </Group>

          {/* компонент для добавления файлов с проверкой формата */}
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
          >
            <Stack gap={4} align="center">
              <Text fw={600}>Бросьте файлы сюда</Text>
              <Text size="sm" className='text-muted'>
                или кликните для загрузки ({files.length}/{MAX_FILES})
              </Text>
            </Stack>
          </Dropzone>

          <Popover 
            width={300}
            position="bottom-end"
          >
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
              <p>Запрещённые файлы можно упаковать в ZIP — но такие архивы могут быть опасны для получателя</p>
            </Popover.Dropdown>
          </Popover>

          {limitMessage && (
            <Alert color="violet" variant="light">
              {limitMessage}
            </Alert>
          )}

          {files.length > 0 && (
            <>
            <Divider  
              my="5" 
            />
            <Stack gap="sm">
              <Group justify="space-between" align="center">
                <Text className='text' fw={600}>Выбранные файлы ({files.length}/{MAX_FILES})</Text>
                <Button 
                  size="xs" 
                  variant="filled" 
                  onClick={clearFiles}
                  color="rgba(207, 56, 66, 1)"
                >
                  Удалить все
                </Button>
              </Group>

              {/* список файлов */}
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
                        style={{
                          color: 'var(--text-strong)'
                        }}
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
          
          {/* ввод пароля */}
          {files.length > 0 && (
            <Flex 
              gap="sm" 
              direction="row"
              wrap="wrap-reverse"
            >
              <PasswordInput
                label="Пароль"
                placeholder="Введите пароль"
                value={password}
                onChange={(event) => setPassword(event.currentTarget.value)}
                className='text'
                style={{ flex: 1 }}
              />
              <Button color="violet" disabled={!password.trim()}>
                Зашифровать и скачать как TAR
              </Button>
            </Flex>
          )}
        </Stack>
      </Paper>
    </main>
  )
}

export default App
