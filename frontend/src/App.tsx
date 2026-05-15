import { Routes, Route, Navigate } from 'react-router-dom';
import Landing from './pages/Landing';
import { Layout } from '@/components/Layout';
import { Home } from '@/pages/Home';
import { DomainDetail } from '@/pages/DomainDetail';
import { Sources } from '@/pages/Sources';
import { Groups, Group } from '@/pages/Groups';
import { Techniques, Technique } from '@/pages/Techniques';

function App() {
  return (
    <Routes>
      {/* Landing renders edge-to-edge with its own nav, outside the old Layout */}
      <Route index element={<Landing />} />

      {/* Everything else keeps the old Layout chrome for now.
          Session 20 will redesign the investigation page chrome to match. */}
      <Route element={<Layout />}>
        <Route path="browse" element={<Home />} />
        <Route path="domains/:name" element={<DomainDetail />} />
        <Route path="sources" element={<Sources />} />
        <Route path="groups" element={<Groups />} />
        <Route path="groups/:attackId" element={<Group />} />
        <Route path="techniques" element={<Techniques />} />
        <Route path="techniques/:attackId" element={<Technique />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;