import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { Home } from '@/pages/Home';
import { DomainDetail } from '@/pages/DomainDetail';
import { Sources } from '@/pages/Sources';
import { Groups, Group } from '@/pages/Groups';
import { Techniques, Technique } from '@/pages/Techniques';

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="domains/:name" element={<DomainDetail />} />
        <Route path="sources" element={<Sources />} />
        <Route path="groups" element={<Groups />} />
        <Route path="groups/:attackId" element={<Group />} />
        <Route path="techniques" element={<Techniques />} />
        <Route path="techniques/:attackId" element={<Technique />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default App;
